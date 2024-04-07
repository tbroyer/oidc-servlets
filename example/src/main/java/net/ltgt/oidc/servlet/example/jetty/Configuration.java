package net.ltgt.oidc.servlet.example.jetty;

import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.openid.connect.sdk.op.ReadOnlyOIDCProviderMetadata;

public record Configuration(
    ReadOnlyOIDCProviderMetadata providerMetadata, //
    String callbackPath,
    ClientAuthentication clientAuthentication //
    ) {
  static final String CONTEXT_ATTRIBUTE_NAME = Configuration.class.getName();
}
