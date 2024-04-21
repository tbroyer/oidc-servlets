package net.ltgt.oidc.servlet;

import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.openid.connect.sdk.op.ReadOnlyOIDCProviderMetadata;
import java.util.function.Function;

public record Configuration(
    ReadOnlyOIDCProviderMetadata providerMetadata, //
    ClientAuthentication clientAuthentication,
    Function<SessionInfo, UserPrincipal> userPrincipalFactory //
    ) {
  public static final String CONTEXT_ATTRIBUTE_NAME = Configuration.class.getName();

  public Configuration(
      ReadOnlyOIDCProviderMetadata providerMetadata, ClientAuthentication clientAuthentication) {
    this(providerMetadata, clientAuthentication, SimpleUserPrincipal::new);
  }
}
