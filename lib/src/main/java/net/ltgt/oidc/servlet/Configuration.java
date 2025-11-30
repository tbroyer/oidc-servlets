package net.ltgt.oidc.servlet;

import static java.util.Objects.requireNonNull;

import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.op.ReadOnlyOIDCProviderMetadata;

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
  private final ClientID clientId;
  private final ClientAuthenticationSupplier clientAuthenticationSupplier;

  public Configuration(
      ReadOnlyOIDCProviderMetadata providerMetadata, ClientAuthentication clientAuthentication) {
    this(
        providerMetadata,
        requireNonNull(clientAuthentication).getClientID(),
        () -> clientAuthentication);
  }

  public Configuration(
      ReadOnlyOIDCProviderMetadata providerMetadata,
      ClientID clientId,
      ClientAuthenticationSupplier clientAuthenticationSupplier) {
    this.providerMetadata = requireNonNull(providerMetadata);
    this.clientId = requireNonNull(clientId);
    this.clientAuthenticationSupplier = requireNonNull(clientAuthenticationSupplier);
  }

  public ReadOnlyOIDCProviderMetadata getProviderMetadata() {
    return providerMetadata;
  }

  public ClientID getClientId() {
    return clientId;
  }

  public ClientAuthenticationSupplier getClientAuthenticationSupplier() {
    return clientAuthenticationSupplier;
  }
}
