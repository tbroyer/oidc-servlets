package net.ltgt.oidc.servlet;

import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.openid.connect.sdk.op.ReadOnlyOIDCProviderMetadata;

public record Configuration(
    ReadOnlyOIDCProviderMetadata providerMetadata, //
    ClientAuthentication clientAuthentication //
    ) {
  public static final String CONTEXT_ATTRIBUTE_NAME = Configuration.class.getName();
}
