rootProject.name = "oidc-servlets"

pluginManagement {
    repositories {
        // gradlePluginPortal redirects to JCenter which is not reliable,
        // prefer Central to JCenter (for the same dependencies)
        // see https://github.com/gradle/gradle/issues/15406
        mavenCentral()
        gradlePluginPortal()
    }
    includeBuild("build-logic")
}

dependencyResolutionManagement {
    repositoriesMode = RepositoriesMode.FAIL_ON_PROJECT_REPOS
    repositories {
        mavenCentral()
    }
}

include("example")
