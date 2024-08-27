plugins {
    id("local.java-conventions")
    `java-library`
    `maven-publish`
    signing
}

dependencies {
    api(libs.jspecify)
    api(libs.errorprone.annotations)
    compileOnlyApi(libs.nullaway.annotations)
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

java {
    withJavadocJar()
    withSourcesJar()
}

tasks {
    javadoc {
        title = "OIDC Servlets API"
    }
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])

            versionMapping {
                usage("java-api") {
                    fromResolutionOf("runtimeClasspath")
                }
                usage("java-runtime") {
                    fromResolutionResult()
                }
            }

            groupId = "net.ltgt.oidc"
            artifactId = "oidc-servlets"
            if (isSnapshot) {
                version = "HEAD-SNAPSHOT"
            }

            pom {
                name = "OIDC Servlets"
                description = "Servlets implementing OpenID Connect, through the Nimbus SDK"
                url = "https://github.com/tbroyer/oidc-servlets"
                licenses {
                    license {
                        name = "The Apache License, Version 2.0"
                        url = "https://www.apache.org/licenses/LICENSE-2.0.txt"
                    }
                }
                developers {
                    developer {
                        name = "Thomas Broyer"
                        email = "t.broyer@ltgt.net"
                    }
                }
                scm {
                    connection = "https://github.com/tbroyer/oidc-servlets.git"
                    developerConnection = "scm:git:ssh://github.com:tbroyer/oidc-servlets.git"
                    url = "https://github.com/tbroyer/oidc-servlets"
                }
            }
        }
    }
}

signing {
    useGpgCmd()
    isRequired = !isSnapshot
    sign(publishing.publications["mavenJava"])
}

inline val Project.isSnapshot
    get() = version == Project.DEFAULT_VERSION
