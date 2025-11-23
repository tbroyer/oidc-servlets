plugins {
    id("local.java-conventions")
    java
}

dependencies {
    implementation(projects.oidcServlets)
    implementation(platform(libs.jetty.bom))
    implementation(platform(libs.jetty.ee10.bom))
    implementation(libs.jetty.servlet)
    implementation(libs.jetty.jsp)
    runtimeOnly(libs.jetty.slf4jImpl)
}

tasks {
    register<JavaExec>("run") {
        classpath(sourceSets.main.map { it.runtimeClasspath })
        mainClass.set("net.ltgt.oidc.servlet.example.jetty.Main")
        systemProperty("example.issuer", "http://auth.localhost:8080/realms/example")
        systemProperty("example.clientId", "app")
        systemProperty("example.clientSecret", "example")
        systemProperty(
            "example.sessionStoreDir",
            layout.buildDirectory
                .dir("session-store")
                .get()
                .asFile,
        )
        args(layout.projectDirectory.dir("src/main/webapp"))
    }
}
