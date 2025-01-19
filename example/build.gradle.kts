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
}

tasks {
    register<JavaExec>("run") {
        classpath(sourceSets.main.map { it.runtimeClasspath })
        mainClass.set("net.ltgt.oidc.servlet.example.jetty.Main")
        systemProperty("example.issuer", "http://localhost:8080/realms/example")
        systemProperty("example.clientId", "app")
        systemProperty("example.clientSecret", "example")
        args(layout.projectDirectory.dir("src/main/webapp"))
    }
}
