rootProject.name = "oidc-servlets-parent"

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

project(":lib").name = "oidc-servlets"

enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")
