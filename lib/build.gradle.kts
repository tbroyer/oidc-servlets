plugins {
    id("local.java-conventions")
    `java-library`
}

dependencies {
    api(libs.checkerQual)
    api(libs.errorprone.annotations)
    compileOnlyApi(libs.nullaway.annotations)
    api(libs.nimbus.oidcSdk)
    api(libs.jakarta.servletApi)
}
