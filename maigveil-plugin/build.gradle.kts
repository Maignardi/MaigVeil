plugins {
    `kotlin-dsl`
    `java-gradle-plugin`
}

group = "io.github.maignardi.maigveil"
version = "1.0.0"

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
    plugins {
        create("maigVeil") {
            id = "io.github.maignardi.maigveil"
            implementationClass = "io.github.maignardi.maigveil.plugin.MaigVeilPlugin"
            displayName = "MaigVeil Android Binary Shield"
            description = "Multi-pass ASM 9 bytecode obfuscator, C++20 VM virtualizer, and anti-tamper suite."
        }
    }
}

dependencies {
    compileOnly("com.android.tools.build:gradle-api:9.4.1")
    implementation("org.ow2.asm:asm:9.7.1")
    implementation("org.ow2.asm:asm-commons:9.7.1")
    implementation("org.ow2.asm:asm-tree:9.7.1")
    implementation("org.ow2.asm:asm-util:9.7.1")

    testImplementation("junit:junit:4.13.2")
}
