plugins {
    id("local.java-conventions")
    java
}

dependencies {
    implementation(libs.checkerQual)
    implementation(libs.errorprone.annotations)
    implementation(libs.nullaway.annotations)
    implementation(platform(libs.jetty.bom))
    implementation(platform(libs.jetty.ee10.bom))
    implementation(libs.jetty.servlet)
}

tasks {
    register<JavaExec>("run") {
        classpath(sourceSets.main.map { it.runtimeClasspath })
        mainClass.set("net.ltgt.oidc.servlet.example.jetty.Main")
        args(layout.projectDirectory.dir("src/main/webapp"))
    }
}
