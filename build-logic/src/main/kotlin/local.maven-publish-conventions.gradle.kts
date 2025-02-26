plugins {
    `maven-publish`
    signing
}

group = "net.ltgt.oidc"

publishing {
    publications {
        withType<MavenPublication>().configureEach {
            pom {
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
}

pluginManager.withPlugin("java") {
    configure<JavaPluginExtension> {
        withJavadocJar()
        withSourcesJar()
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
            }
        }
    }

    signing {
        sign(publishing.publications["mavenJava"])
    }
}
pluginManager.withPlugin("java-platform") {
    publishing {
        publications {
            create<MavenPublication>("mavenJavaPlatform") {
                from(components["javaPlatform"])
            }
        }
    }

    signing {
        sign(publishing.publications["mavenJavaPlatform"])
    }
}

inline val Project.isSnapshot
    get() = version.toString().endsWith("-SNAPSHOT")
