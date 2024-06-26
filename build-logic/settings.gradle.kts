rootProject.name = "oidc-servlets-build-logic"

pluginManagement {
    repositories {
        // gradlePluginPortal redirects to JCenter which is not reliable,
        // prefer Central to JCenter (for the same dependencies)
        // see https://github.com/gradle/gradle/issues/15406
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode = RepositoriesMode.FAIL_ON_PROJECT_REPOS
    repositories {
        // gradlePluginPortal redirects to JCenter which is not reliable,
        // prefer Central to JCenter (for the same dependencies)
        // see https://github.com/gradle/gradle/issues/15406
        mavenCentral()
        gradlePluginPortal()
    }
    versionCatalogs {
        create("libs") {
            from(files("../gradle/libs.versions.toml"))
        }
    }
}

