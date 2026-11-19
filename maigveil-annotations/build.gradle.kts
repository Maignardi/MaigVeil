import com.vanniktech.maven.publish.JavadocJar
import com.vanniktech.maven.publish.KotlinJvm
import com.vanniktech.maven.publish.SourcesJar

plugins {
    alias(libs.plugins.kotlin.jvm)
    `java-library`
    alias(libs.plugins.vanniktech.maven.publish)
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_11)
    }
}

mavenPublishing {
    configure(
        KotlinJvm(
            javadocJar = JavadocJar.Javadoc(),
            sourcesJar = SourcesJar.Sources()
        )
    )

    pom {
        name.set("MaigVeil Annotations")
        description.set("BINARY-retained compile-time annotations (@VeilObfuscate, @VeilVirtualize, @VeilControlFlow, @VeilString, @VeilAsset, @VeilIgnore) for the MaigVeil Android binary shield.")
    }
}
