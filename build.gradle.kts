plugins {
    id("local.common-conventions")
    alias(libs.plugins.nexusPublish)
}

nexusPublishing {
    packageGroup = "net.ltgt.oidc"
    useStaging = !version.toString().endsWith("-SNAPSHOT")
    repositories {
        sonatype()
    }
}
