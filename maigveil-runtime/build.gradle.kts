import com.vanniktech.maven.publish.AndroidSingleVariantLibrary
import com.vanniktech.maven.publish.JavadocJar
import com.vanniktech.maven.publish.SourcesJar

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.vanniktech.maven.publish)
}

android {
    namespace = "io.github.maignardi.maigveil.runtime"
    compileSdk = 37

    defaultConfig {
        minSdk = 24
        consumerProguardFiles("consumer-rules.pro")

        externalNativeBuild {
            cmake {
                cppFlags("-std=c++20", "-fvisibility=hidden", "-Os", "-fno-exceptions", "-ffunction-sections", "-fdata-sections")
                arguments("-DANDROID_STL=c++_static")
            }
        }
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86")
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}

dependencies {
    api(project(":maigveil-annotations"))
    implementation(libs.androidx.core.ktx)
    testImplementation(libs.junit)
}

mavenPublishing {
    configure(
        AndroidSingleVariantLibrary(
            javadocJar = JavadocJar.Javadoc(),
            sourcesJar = SourcesJar.Sources(),
            variant = "release"
        )
    )

    pom {
        name.set("MaigVeil Runtime")
        description.set("Native C++20 polymorphic VM, ChaCha20-Poly1305 asset decryptor, direct-syscall APK signature verifier, and Zero-Trace secret runtime for MaigVeil.")
    }
}
