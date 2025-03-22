plugins {
    id("local.java-conventions")
    id("local.maven-publish-conventions")
    `java-library`
    `java-test-fixtures`
}

dependencies {
    api(platform(projects.oidcServletsBom))

    api(libs.jspecify)
    api(libs.errorprone.annotations)
    api(libs.nimbus.oidcSdk)
    api(libs.jakarta.servletApi)

    testFixturesApi(libs.junitJupiter.api)
    testFixturesApi(platform(libs.jetty.bom))
    testFixturesApi(platform(libs.jetty.ee10.bom))
    testFixturesApi(libs.jetty.servlet)
    testFixturesApi(libs.selenium)
    testFixturesImplementation(libs.truth)
}

testing {
    suites {
        withType<JvmTestSuite>().configureEach {
            useJUnitJupiter(libs.versions.junitJupiter)
        }
        named<JvmTestSuite>("test") {
            dependencies {
                implementation(libs.truth)
            }
        }
        register<JvmTestSuite>("functionalTest") {
            dependencies {
                implementation(project())
                implementation(testFixtures(project()))
                implementation(libs.truth)
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

// Don't publish test fixtures
// https://docs.gradle.org/current/userguide/java_testing.html#ex-disable-publishing-of-test-fixtures-variants
val javaComponent = components["java"] as AdhocComponentWithVariants
javaComponent.withVariantsFromConfiguration(configurations.testFixturesApiElements.get()) { skip() }
javaComponent.withVariantsFromConfiguration(configurations.testFixturesRuntimeElements.get()) { skip() }
