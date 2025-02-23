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

fun include(
    projectPath: String,
    projectDir: String,
) {
    include(projectPath)
    project(projectPath).projectDir = file(projectDir)
}
include(":oidc-servlets", "lib")
include(":oidc-servlets-rs", "rs")
include(":example")

enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")
