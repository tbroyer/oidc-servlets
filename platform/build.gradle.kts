plugins {
    id("local.common-conventions")
    id("local.maven-publish-conventions")
    `java-platform`
}

dependencies {
    constraints {
        api(projects.oidcServlets)
        api(projects.oidcServletsRs)
    }
}

publishing {
    publications {
        withType<MavenPublication>().configureEach {
            pom {
                name = "OIDC Servlets BOM"
                description = "Bill of Materials for OIDC-Servlets libraries"
            }
        }
    }
}
