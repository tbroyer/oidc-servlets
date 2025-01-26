package net.ltgt.oidc.servlet;

import static java.util.Objects.requireNonNull;

import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.openid.connect.sdk.op.ReadOnlyOIDCProviderMetadata;
import java.util.function.Function;

/**
 * Contains the OpenID Connect-related configuration.
 *
 * <p>An instance of this class needs to be registered as a {@link jakarta.servlet.ServletContext
 * ServletContext} attribute under the name {@link #CONTEXT_ATTRIBUTE_NAME}.
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect Core 1.0</a>
 */
public class Configuration {
  public static final String CONTEXT_ATTRIBUTE_NAME = Configuration.class.getName();

  private final ReadOnlyOIDCProviderMetadata providerMetadata;
  private final ClientAuthentication clientAuthentication;
  private final Function<SessionInfo, UserPrincipal> userPrincipalFactory;

  public Configuration(
      ReadOnlyOIDCProviderMetadata providerMetadata,
      ClientAuthentication clientAuthentication,
      Function<SessionInfo, UserPrincipal> userPrincipalFactory) {
    this.providerMetadata = requireNonNull(providerMetadata);
    this.clientAuthentication = requireNonNull(clientAuthentication);
    this.userPrincipalFactory = requireNonNull(userPrincipalFactory);
  }

  /** Constructs a configuration instance that creates instances of {@link SimpleUserPrincipal}. */
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
    return requireNonNull(userPrincipalFactory.apply(sessionInfo));
  }
}
