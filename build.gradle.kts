// Top-level build file where you can add configuration options common to all sub-projects/modules.
plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.compose) apply false
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.vanniktech.maven.publish) apply false
}

subprojects {
    pluginManager.withPlugin("com.vanniktech.maven.publish") {
        val groupId = providers.gradleProperty("GROUP").get()
        val versionName = providers.gradleProperty("VERSION_NAME").get()

        group = groupId
        version = versionName

        val hasSigningKey =
            providers.gradleProperty("signingInMemoryKey").isPresent ||
                providers.environmentVariable("ORG_GRADLE_PROJECT_signingInMemoryKey").isPresent ||
                providers.gradleProperty("signing.keyId").isPresent
        val publishingToCentral = gradle.startParameter.taskNames.any {
            it.contains("MavenCentral", ignoreCase = true)
        }

        extensions.configure<com.vanniktech.maven.publish.MavenPublishBaseExtension> {
            publishToMavenCentral(automaticRelease = true)
            if (hasSigningKey || publishingToCentral) {
                signAllPublications()
            }
        }
    }
}
