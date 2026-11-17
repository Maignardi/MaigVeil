plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "io.github.maignardi.maigveil.runtime"
    compileSdk = 37

    defaultConfig {
        minSdk = 24
        consumerProguardFiles("consumer-rules.pro")

        externalNativeBuild {
            cmake {
                cppFlags("-std=c++20", "-fvisibility=hidden", "-O3", "-ffunction-sections", "-fdata-sections")
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
    implementation(project(":maigveil-annotations"))
    implementation(libs.androidx.core.ktx)
    testImplementation(libs.junit)
}
