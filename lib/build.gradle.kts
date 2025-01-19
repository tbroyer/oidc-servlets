plugins {
    id("local.java-conventions")
    id("local.maven-publish-conventions")
    `java-library`
}

dependencies {
    api(libs.jspecify)
    api(libs.errorprone.annotations)
    api(libs.nimbus.oidcSdk)
    api(libs.jakarta.servletApi)
}

testing {
    suites {
        withType<JvmTestSuite>().configureEach {
            useJUnitJupiter(libs.versions.junitJupiter)
        }
        register<JvmTestSuite>("functionalTest") {
            dependencies {
                implementation(project())
                implementation(platform(libs.jetty.bom))
                implementation(platform(libs.jetty.ee10.bom))
                implementation(libs.jetty.servlet)
                implementation(libs.selenium)
                implementation(libs.truth) {
                    // See https://github.com/google/truth/issues/333
                    exclude(group = "junit", module = "junit")
                }
            }
            targets.configureEach {
                testTask {
                    systemProperty("test.port", 8000)
                    systemProperty("test.issuer", "http://localhost:8080/realms/example")
                    systemProperty("test.clientId", "app")
                    systemProperty("test.clientSecret", "example")
                }
            }
        }
    }
}

tasks {
    javadoc {
        title = "OIDC Servlets API"
    }
}

publishing {
    publications {
        withType<MavenPublication>().configureEach {
            pom {
                name = "OIDC Servlets"
                description = "Servlets implementing OpenID Connect, through the Nimbus SDK"
            }
        }
    }
}
