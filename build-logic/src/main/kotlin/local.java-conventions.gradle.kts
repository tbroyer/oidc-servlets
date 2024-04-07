import net.ltgt.gradle.errorprone.errorprone
import net.ltgt.gradle.nullaway.nullaway

plugins {
    id("local.common-conventions")
    `java-base`
    id("net.ltgt.errorprone")
    id("net.ltgt.nullaway")
    id("de.thetaphi.forbiddenapis")
    id("org.gradlex.jvm-dependency-conflict-resolution")
}

dependencies {
    errorprone(project.versionCatalogs.named("libs").findBundle("errorprone").orElseThrow())
}

nullaway {
    annotatedPackages.add("net.ltgt.oidc")
}

forbiddenApis {
    bundledSignatures = setOf("jdk-unsafe", "jdk-deprecated", "jdk-internal", "jdk-non-portable", "jdk-system-out")
}

java {
    sourceCompatibility = JavaVersion.VERSION_21
}

// Configure toolchain only if needed
if (!JavaVersion.current().isCompatibleWith(java.sourceCompatibility)) {
    java {
        toolchain {
            languageVersion = JavaLanguageVersion.of(java.sourceCompatibility.majorVersion)
        }
    }
}

tasks.withType<JavaCompile>().configureEach {
    options.release = java.sourceCompatibility.majorVersion.toInt()
    options.encoding = "UTF-8"
    options.compilerArgs.addAll(arrayOf("-Werror", "-Xlint:all,-fallthrough,-serial"))
    options.errorprone {
        nullaway {
            knownInitializers.appendAll(
                "jakarta.servlet.Servlet.init",
                "jakarta.servlet.GenericServlet.init",
                "jakarta.servlet.Filter.init",
                "jakarta.servlet.GenericFilter.init",
            )
        }
    }
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}

spotless {
    java {
        googleJavaFormat(project.versionCatalogs.named("libs").findVersion("googleJavaFormat").orElseThrow().requiredVersion)
    }
}
