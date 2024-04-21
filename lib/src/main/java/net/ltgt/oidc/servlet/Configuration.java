package net.ltgt.oidc.servlet;

import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.openid.connect.sdk.op.ReadOnlyOIDCProviderMetadata;
import java.util.function.Function;

public class Configuration {
  public static final String CONTEXT_ATTRIBUTE_NAME = Configuration.class.getName();

  private final ReadOnlyOIDCProviderMetadata providerMetadata;
  private final ClientAuthentication clientAuthentication;
  private final Function<SessionInfo, UserPrincipal> userPrincipalFactory;

  public Configuration(
      ReadOnlyOIDCProviderMetadata providerMetadata,
      ClientAuthentication clientAuthentication,
      Function<SessionInfo, UserPrincipal> userPrincipalFactory) {
    this.providerMetadata = providerMetadata;
    this.clientAuthentication = clientAuthentication;
    this.userPrincipalFactory = userPrincipalFactory;
  }

  public Configuration(
      ReadOnlyOIDCProviderMetadata providerMetadata, ClientAuthentication clientAuthentication) {
    this(providerMetadata, clientAuthentication, SimpleUserPrincipal::new);
  }

  public ReadOnlyOIDCProviderMetadata getProviderMetadata() {
    return providerMetadata;
  }

  public ClientAuthentication getClientAuthentication() {
    return clientAuthentication;
  }

  public UserPrincipal createUserPrincipal(SessionInfo sessionInfo) {
    return userPrincipalFactory.apply(sessionInfo);
  }
}
