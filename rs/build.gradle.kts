plugins {
    id("local.java-conventions")
    id("local.maven-publish-conventions")
    `java-library`
    alias(libs.plugins.testRetry)
}

dependencies {
    api(platform(projects.oidcServletsBom))

    api(projects.oidcServlets)
    api(libs.jakarta.rsApi)
    api(libs.jakarta.annotationApi)
}

testing {
    suites {
        withType<JvmTestSuite>().configureEach {
            useJUnitJupiter(libs.versions.junitJupiter)
        }
        register<JvmTestSuite>("functionalTest") {
            dependencies {
                implementation(project())
                implementation(testFixtures(projects.oidcServlets))
                implementation(platform(libs.resteasy.bom))
                implementation(libs.resteasy.core)
                implementation(libs.truth)
            }
            targets.configureEach {
                testTask {
                    // Both tasks bind to the same test.port (due to Keycloak configuration)
                    mustRunAfter("${projects.oidcServlets.path}:functionalTest")

                    systemProperty("test.port", 8000)
                    systemProperty("test.issuer", "http://localhost:8080/realms/example")
                    systemProperty("test.clientId", "app")
                    systemProperty("test.clientSecret", "example")

                    retry {
                        maxRetries = 2
                    }
                }
            }
        }
    }
}

tasks {
    javadoc {
        title = "OIDC Servlets+RS API"
    }
}

mavenPublishing {
    pom {
        name = "OIDC Servlets+RS"
        description = "Jakarta RS filters as a companion library to OIDC-Servlets"
    }
}
