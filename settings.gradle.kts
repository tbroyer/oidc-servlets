rootProject.name = "oidc-servlets"

pluginManagement {
    includeBuild("build-logic")
}

dependencyResolutionManagement {
    repositoriesMode = RepositoriesMode.FAIL_ON_PROJECT_REPOS
    repositories {
        mavenCentral()
    }
}

include("lib", "example")

enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")
