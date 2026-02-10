/*
 * Copyright © 2026 Thomas Broyer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.ltgt.oidc.servlet;

import static java.util.Objects.requireNonNull;

import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.ClientSecretJWT;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.PKITLSClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.auth.SelfSignedTLSClientAuthentication;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.op.ReadOnlyOIDCProviderMetadata;

/**
 * Contains the OpenID Connect-related configuration.
 *
 * <p>An instance of this class needs to be registered as a {@link jakarta.servlet.ServletContext
 * ServletContext} attribute under the name {@link #CONTEXT_ATTRIBUTE_NAME}.
 *
 * <h3>Client Authentication</h3>
 *
 * <p>Client authentication is used to authenticate the application against the identity provider
 * when calling the token endpoint and revocation endpoint.
 *
 * <p>This corresponds to the {@code token_endpoint_auth_method} client metadata field.
 *
 * <h4>Plain client secret</h4>
 *
 * <p>To use a plain client secret, use a {@link ClientSecretBasic} instance (for the {@code
 * client_secret_basic} authentication method), or a {@link ClientSecretPost} instance (for the
 * {@code client_secret_post} authentication method).
 *
 * <h4>Mutual-TLS (client certificate)</h4>
 *
 * <p>To use Mutual-TLS, following <a href="https://datatracker.ietf.org/doc/html/rfc8705">RFC
 * 8705</a>, use a {@link PKITLSClientAuthentication} instance (for the {@code tls_client_auth}
 * authentication method), or a {@link SelfSignedTLSClientAuthentication} instance (for the {@code
 * self_signed_tls_client_auth} authentication method).
 *
 * <p>The OIDC provider metadata needs to have its {@code mtls_endpoint_aliases} <i>resolved</i>
 * (i.e. the {@code *_endpoint} fields of the provider metadata have been replaced with the values
 * of the corresponding {@code mtls_endpoint_aliases} subfields). You can do that by passing the
 * original provider metadata to {@link
 * Utils#resolveMtlsEndpointAliases(ReadOnlyOIDCProviderMetadata)}.
 *
 * <h4>JWT</h4>
 *
 * <p>To use JWTs, following <a href="https://datatracker.ietf.org/doc/tml/rfc7523">RFC 7523</a>,
 * use a {@link ClientAuthenticationSupplier} that will return either {@link ClientSecretJWT}
 * instances (for the {@code client_secret_jwt} authentication method) or {@link PrivateKeyJWT}
 * instances (for the {@code private_key_jwt} authentication method). A new instance has to be
 * returned each time the supplier's {@link ClientAuthenticationSupplier#getClientAuthentication()
 * getClientAuthentication()} is called, as each JWT is only usable once, and for a limited time.
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect Core 1.0</a>
 */
public final class Configuration {
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
