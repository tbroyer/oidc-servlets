import org.gradle.api.publish.maven.MavenPublication
import org.gradle.kotlin.dsl.*

plugins {
    `java`
    `maven-publish`
    signing
}

group = "net.ltgt.oidc"

java {
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
    sign(publishing.publications["mavenJava"])
}

inline val Project.isSnapshot
    get() = version.toString().endsWith("-SNAPSHOT")
