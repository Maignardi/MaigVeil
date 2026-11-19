import java.util.Properties

plugins {
    `kotlin-dsl`
    alias(libs.plugins.gradle.plugin.publish)
}

val rootProps = Properties().apply {
    file("../gradle.properties").inputStream().use { load(it) }
}

group = rootProps.getProperty("GROUP")
version = rootProps.getProperty("VERSION_NAME")

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

gradlePlugin {
    website.set("https://github.com/Maignardi/MaigVeil")
    vcsUrl.set("https://github.com/Maignardi/MaigVeil.git")
    plugins {
        create("maigVeil") {
            id = "io.github.maignardi.maigveil"
            implementationClass = "io.github.maignardi.maigveil.plugin.MaigVeilPlugin"
            displayName = "MaigVeil Android Binary Shield"
            description = "Multi-pass ASM 9 bytecode obfuscator, C++20 polymorphic VM virtualizer, ChaCha20-Poly1305 asset shield, and anti-tamper Gradle plugin for Android."
            tags.set(listOf("android", "security", "obfuscation", "asm", "native", "anti-tamper"))
        }
    }
}

dependencies {
    compileOnly("com.android.tools.build:gradle-api:9.4.1")
    implementation(libs.asm.core)
    implementation(libs.asm.commons)
    implementation(libs.asm.tree)
    implementation(libs.asm.util)

    testImplementation(libs.junit)
}
