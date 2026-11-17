# MaigVeil

**Multi-Pass Android Binary Shield — Gradle Plugin + ASM 9 Bytecode Transformer + Native C++20 Polymorphic VM & Anti-Tamper Engine**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![AGP](https://img.shields.io/badge/AGP-8.7%2B%20%2F%209.4-green.svg)](https://developer.android.com/build)
[![C++20](https://img.shields.io/badge/Native-C%2B%2B20%20NDK-orange.svg)](maigveil-runtime/src/main/cpp/CMakeLists.txt)

MaigVeil (`io.github.maignardi.maigveil`) is a compile-time and runtime Android binary hardening suite designed to go far beyond R8/ProGuard name minification. It protects business logic, secrets, control flow, API call graphs, and bundled assets against static decompilers (**JADX**, **Ghidra**, **IDA Pro**) and dynamic instrumentation (**Frida**, **Xposed**, memory dumping).

---

## Architecture

MaigVeil is structured as a 4-module Gradle project compatible with **Gradle Configuration Cache**, **Incremental Builds**, and **R8 Full Mode**:

```
MaigVeil/
├── maigveil-annotations/   # BINARY-retained annotations (@VeilVirtualize, @VeilControlFlow, etc.)
├── maigveil-plugin/        # Gradle Plugin + Multi-Pass ASM 9 Engine + AssetShieldTask
├── maigveil-runtime/       # Kotlin Runtime API + C++20 Native Core (libmaigveil.so)
└── app/                    # Jetpack Compose Showcase, Telemetry & Microsecond Benchmark Suite
```

### 6 Coupled Layers of Defense

| Layer | Component | Mechanism |
| :--- | :--- | :--- |
| **1. Polymorphic String & Constant Encryption** | `StringEncryptionPass` | Strips `ConstantValue` from `static final String` fields (initializing in `<clinit>`) and encrypts `LDC` literals using a per-build randomized **ARX (Add-Rotate-XOR)** schedule bound to a 256-bit `BuildEntropySeed`. |
| **2. Control Flow Flattening & Opaque Predicates** | `ControlFlowPass` | Splits basic blocks, flattens control flow into a `LOOKUPSWITCH` state machine with encrypted state IDs, and injects number-theoretic opaque predicates (`(x*(x+1)) & 1 == 0`, `((7*x*x-1) & 3) != ((x*x) & 3)`) seeded from non-constant runtime entropy (`System.nanoTime()`). |
| **3. Call Graph Hiding (`INVOKEDYNAMIC`)** | `CallIndirectionPass` | Rewrites sensitive `INVOKESTATIC` / `INVOKEVIRTUAL` calls (e.g. `javax/crypto/*`, `java/security/*`, `okhttp3/*`) into `INVOKEDYNAMIC` instructions resolved at runtime by `MaigVeilBootstrap`. |
| **4. C++20 Polymorphic Bytecode VM** | `VirtualizationPass` + `vm_engine.cpp` | Compiles `@VeilVirtualize` methods into custom bytecode using a **per-build shuffled 256-entry opcode table** and replaces the JVM method body with a JNI call to the C++20 interpreter inside `libmaigveil.so`. |
| **5. Authenticated Asset Shield** | `AssetShieldTask` + `MaigVeilAssets` | Encrypts matching `assets/` files (`.json`, `.pem`, ML models, etc.) at build time using **RFC 8439 ChaCha20-Poly1305** (`MVAS` envelope) and packages the encrypted `mv_vault.bin`. |
| **6. Native Self-Defense & Silent Anti-Repackaging** | `apk_sig_verifier.cpp` + `anti_tamper.cpp` | Uses **inline direct syscalls** (`aarch64` `svc #0` / `x86_64` `syscall`) to read `/proc/self/maps` and extract the APK Signing Scheme v2/v3 certificate SHA-256. Resigned APKs silently derive wrong keys without `exit(0)` crashes. Also verifies `.text` integrity, scans prologues for inline hook trampolines, checks `TracerPid`, and wipes `mmap`+`mlock` Zero-Trace secrets with compiler barriers. |

---

## Comparison with Existing Tools

| Capability | R8 / ProGuard | MaigVeil | Commercial Tier-1 (DexGuard / Promon) |
| :--- | :---: | :---: | :---: |
| Identifier Renaming & Shrinking | Yes | Compatible (runs alongside R8) | Yes |
| Polymorphic String Encryption | No | Yes (per-build ARX + `ConstantValue` stripping) | Yes (per-build) |
| Control Flow Flattening + Opaque Predicates | No | Yes (`LOOKUPSWITCH` + Level 1/2 math invariants) | Yes |
| `INVOKEDYNAMIC` Call Indirection | No | Yes (`MaigVeilBootstrap`) | Yes |
| Native C++20 Bytecode Virtualization | No | Yes (per-build shuffled opcodes) | Yes (custom VM + per-build `.so` codegen) |
| ChaCha20-Poly1305 Asset Encryption | No | Yes (`MaigVeilAssets.open`) | Yes |
| Direct-Syscall APK Sig v2/v3 Binding | No | Yes (silent key corruption) | Yes |
| Zero-Trace `mmap`/`mlock` Secret Buffer | No | Yes (`MaigVeil.withSecret`) | Varies |
| Closed-Source Per-Build Native Binary Polymorphism | No | Open-source shared C++20 core | Yes (cloud/binary compiler) |

---

## Quick Start

### 1. Add MaigVeil from JitPack (External Projects)

In `settings.gradle.kts`:
```kotlin
pluginManagement {
    repositories {
        gradlePluginPortal()
        google()
        mavenCentral()
        maven { url = uri("https://jitpack.io") }
    }
    resolutionStrategy {
        eachPlugin {
            if (requested.id.id == "io.github.maignardi.maigveil") {
                useModule("com.github.Maignardi.MaigVeil:maigveil-plugin:1.0.0")
            }
        }
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven { url = uri("https://jitpack.io") }
    }
}
```

In `app/build.gradle.kts`:
```kotlin
plugins {
    alias(libs.plugins.android.application)
    id("io.github.maignardi.maigveil")
}

android {
    defaultConfig {
        minSdk = 26 // Required for INVOKEDYNAMIC in DEX
    }
}

dependencies {
    implementation("com.github.Maignardi.MaigVeil:maigveil-annotations:1.0.0")
    implementation("com.github.Maignardi.MaigVeil:maigveil-runtime:1.0.0")
}
```

*(If developing locally from source inside a monorepo, use `includeBuild("maigveil-plugin")` and `project(":maigveil-annotations")` / `project(":maigveil-runtime")` instead.)*

Configure the `maigVeil { ... }` DSL in `app/build.gradle.kts`:

maigVeil {
    enabled.set(true)
    profile.set(io.github.maignardi.maigveil.plugin.VeilProfile.PARANOID)
    targetPackages.set(listOf("com.example.fintech.core"))
    excludePackages.set(listOf("com.example.fintech.ui.theme"))

    stringObfuscation {
        enabled.set(true)
        encryptConstVals.set(true)
        zeroTraceMode.set(true)
    }

    controlFlow {
        enabled.set(true)
        flatteningProbability.set(80)
        opaquePredicatesLevel.set(2)
    }

    callIndirection {
        enabled.set(true)
        targetApis.set(listOf("javax/crypto/*", "okhttp3/*", "java/security/*"))
    }

    virtualization {
        enabled.set(true)
    }

    assets {
        encryptFiles.set(listOf("config/*.json", "certs/*.pem"))
    }

    antiTamper {
        bindApkSigningCertSha256.set("AUTO_EXTRACT_FROM_SIGNING_CONFIG")
        stripKotlinMetadata.set(true)
        stripAnnotations.set(true)
    }
}

dependencies {
    implementation(project(":maigveil-annotations"))
    implementation(project(":maigveil-runtime"))
}
```

### 2. Annotate Sensitive Code

```kotlin
@VeilObfuscate(profile = VeilProfileLevel.PARANOID)
@VeilString(zeroTrace = true)
object LicenseEngine {

    const val API_SECRET = "sk_live_protected_value"

    @VeilVirtualize
    @JvmStatic
    fun verifyChecksum(userId: Int, salt: Int): Int {
        // Compiled into shuffled C++20 VM bytecode; JVM body is removed
        return ((userId xor 0x5A3C9E11) + (salt * 31)) and 0x7FFFFFFF
    }

    @VeilControlFlow(flatteningProbability = 100, opaquePredicatesLevel = 2)
    @JvmStatic
    fun evaluateRisk(amount: Int, velocity: Int): Int {
        return if (amount > 10_000) 80 else velocity * 5
    }
}
```

### 3. Mobile Usage Examples (Copy-Paste Ready)

`MaigVeilInitProvider` initializes the native C++20 engine automatically before `Application.onCreate()`. See [FintechSecurityExamples.kt](app/src/main/java/com/maignardi/maigveil/protected_core/FintechSecurityExamples.kt) for the full runnable showcase.

```kotlin
// 1. Zero-Trace Secret (never allocated as a java.lang.String on the JVM heap)
val authHeader = MaigVeil.withZeroTraceSecret("Bearer mv_live_ephemeral_secret") { chars ->
    // Decrypted straight into mlock'd native memory, wiped & munmapped on exit
    computeHmac(chars)
}

// 2. Virtualized Business Logic (runs inside C++20 libmaigveil.so VM)
@VeilVirtualize
@JvmStatic
fun isPremiumEntitlementValid(accountId: Int, code: Int): Int {
    val expected = ((accountId xor 0x2026CAFE) + 7919) and 0x7FFFFFFF
    return if (code == expected) 1 else 0
}

// 3. Encrypted Assets (ChaCha20-Poly1305)
val configJson = MaigVeilAssets.open(context, "config/secret_config.json")
    .bufferedReader().use { it.readText() }

// 4. Native Self-Defense Telemetry
val status = MaigVeil.status()
check(status.isHealthy) { "Tamper or hook detected!" }
```

---

## Building & Testing

```bash
# Run ASM bytecode pass & RFC 8439 crypto tests
./gradlew -p maigveil-plugin test

# Run host C++20 native crypto, white-box & zero-trace tests
clang++ -std=c++20 -O2 \
  maigveil-runtime/src/test/cpp/native_crypto_test.cpp \
  maigveil-runtime/src/main/cpp/crypto_engine.cpp \
  -o /tmp/mv_native_test && /tmp/mv_native_test

# Build the showcase Android APK (compiles libmaigveil.so for 4 ABIs + runs all MaigVeil passes)
./gradlew :app:assembleDebug
```

---

## Security Considerations

- **White-Box Root Customization**: Because this repository is open-source, customize the 256-bit white-box lanes in `MaigVeilCrypto.kt` and `compile_time_obf.hpp` for production releases so attackers cannot reuse the public default root shares.
- **Release Builds**: Always test release APKs signed with your production keystore (`bindApkSigningCertSha256 = "AUTO_EXTRACT_FROM_SIGNING_CONFIG"` or explicit SHA-256 hex) so `mv_vault.bin` binds to your release certificate.
