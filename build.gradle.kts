plugins {
    id("local.common-conventions")
    alias(libs.plugins.nexusPublish)
}

nexusPublishing {
    packageGroup = "net.ltgt.oidc"
    useStaging = (version != Project.DEFAULT_VERSION)
    repositories {
        sonatype()
    }
}
