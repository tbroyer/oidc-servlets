plugins {
    id("local.common-conventions")
    alias(libs.plugins.nexusPublish)
}

nexusPublishing {
    packageGroup = "net.ltgt.oidc"
    useStaging = !version.toString().endsWith("-SNAPSHOT")
    repositories {
        // see https://central.sonatype.org/publish/publish-portal-ossrh-staging-api/#configuration
        sonatype {
            nexusUrl.set(uri("https://ossrh-staging-api.central.sonatype.com/service/local/"))
            snapshotRepositoryUrl.set(uri("https://central.sonatype.com/repository/maven-snapshots/"))
        }
    }
}
