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

import com.google.common.testing.NullPointerTester;
import com.google.common.testing.NullPointerTester.Visibility;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.JWKGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.PushedAuthorizationSuccessResponse;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;
import com.nimbusds.oauth2.sdk.http.HTTPRequestSender;
import com.nimbusds.oauth2.sdk.http.ReadOnlyHTTPRequest;
import com.nimbusds.oauth2.sdk.http.ReadOnlyHTTPResponse;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.op.ReadOnlyOIDCProviderMetadata;
import java.io.IOException;
import java.lang.reflect.Modifier;
import java.net.URI;
import java.sql.Date;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.function.Consumer;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

public class NullSatefyTest {
  private <T> void testPublicApi(NullPointerTester tester, Class<T> cls, @Nullable T instance) {
    tester.testStaticMethods(cls, Visibility.PROTECTED);
    if (!Modifier.isAbstract(cls.getModifiers())) {
      tester.testConstructors(cls, Visibility.PROTECTED);
    }
    if (instance != null) {
      tester.testInstanceMethods(instance, Visibility.PROTECTED);
    }
  }

  @Test
  void testConfiguration() {
    var oidcProviderMetadata =
        new OIDCProviderMetadata(
            new Issuer("issuer"),
            List.of(SubjectType.PUBLIC),
            URI.create("https://example.com/jwks"));
    var clientAuthentication = new ClientSecretBasic(new ClientID(), new Secret());
    var tester =
        new NullPointerTester()
            .setDefault(ReadOnlyOIDCProviderMetadata.class, oidcProviderMetadata)
            .setDefault(ClientAuthentication.class, clientAuthentication);
    testPublicApi(
        tester, Configuration.class, new Configuration(oidcProviderMetadata, clientAuthentication));
    // XXX: put in its own test method? It's just an interface for now
    testPublicApi(tester, ClientAuthenticationSupplier.class, null);
  }

  @Test
  void testAuthenticationRedirector() throws Exception {
    var oidcProviderMetadata =
        new OIDCProviderMetadata(
            new Issuer("issuer"),
            List.of(SubjectType.PUBLIC),
            URI.create("https://example.com/jwks"));
    oidcProviderMetadata.setAuthorizationEndpointURI(URI.create("https://example.com/authorize"));
    var clientAuthentication = new ClientSecretBasic(new ClientID(), new Secret());
    var configuration = new Configuration(oidcProviderMetadata, clientAuthentication);
    var tester =
        new NullPointerTester() //
            .setDefault(Configuration.class, configuration)
            .setDefault(URI.class, URI.create("https://example.com"))
            // @ForOverride methods
            .ignore(
                AuthenticationRedirector.class.getDeclaredMethod(
                    "configureAuthenticationRequest", AuthenticationRequest.Builder.class))
            .ignore(
                AuthenticationRedirector.class.getDeclaredMethod(
                    "sendRedirect", AuthenticationRequest.class, Consumer.class));
    testPublicApi(
        tester,
        AuthenticationRedirector.class,
        new AuthenticationRedirector(configuration, "/callback"));
  }

  @Test
  void testDPoPSupport() throws Exception {
    var keyGenerator = new ECKeyGenerator(Curve.P_256);
    var tester =
        new NullPointerTester()
            .setDefault(JWKGenerator.class, keyGenerator)
            .setDefault(JWK.class, keyGenerator.generate())
            .setDefault(JWSAlgorithm.class, JWSAlgorithm.ES256)
            .setDefault(
                JWKThumbprintConfirmation.class, new JWKThumbprintConfirmation(Base64URL.from("")));
    testPublicApi(tester, DPoPSupport.class, null);
  }

  @Test
  void testDPoPNonceStore() {
    var tester =
        new NullPointerTester() //
            .setDefault(URI.class, URI.create("https://example.com/"));
    testPublicApi(tester, DPoPNonceStore.class, null);
    testPublicApi(tester, SingleDPoPNonceStore.class, null);
    testPublicApi(tester, PerUriDPoPNonceStore.class, null);
  }

  @Test
  void testUserPrincipal() throws Exception {
    var idTokenClaims =
        new IDTokenClaimsSet(
            new Issuer("issuer"),
            new Subject("sub"),
            List.of(new Audience("audience")),
            Date.from(Instant.now().plus(10, ChronoUnit.MINUTES)),
            Date.from(Instant.now().minus(5, ChronoUnit.MINUTES)));
    var idToken = new PlainJWT(idTokenClaims.toJWTClaimsSet());
    var sessionInfo = new SessionInfo(idToken, idTokenClaims, new UserInfo(new Subject("sub")));
    var tester =
        new NullPointerTester()
            .setDefault(SessionInfo.class, sessionInfo)
            // hasRole might not throw a long as it returns false for a null role
            .ignore(SimpleUserPrincipal.class.getMethod("hasRole", String.class))
            .ignore(KeycloakUserPrincipal.class.getMethod("hasRole", String.class));
    testPublicApi(tester, UserPrincipalFactory.class, null);
    testPublicApi(tester, UserPrincipal.class, null);
    testPublicApi(tester, SimpleUserPrincipal.class, new SimpleUserPrincipal(sessionInfo));
    testPublicApi(tester, KeycloakUserPrincipal.class, new KeycloakUserPrincipal(sessionInfo));
  }

  @Test
  void testOAuthTokenHandler() {
    var oidcProviderMetadata =
        new OIDCProviderMetadata(
            new Issuer("issuer"),
            List.of(SubjectType.PUBLIC),
            URI.create("https://example.com/jwks"));
    var clientAuthentication = new ClientSecretBasic(new ClientID(), new Secret());
    var tester =
        new NullPointerTester()
            .setDefault(
                Configuration.class, new Configuration(oidcProviderMetadata, clientAuthentication));
    testPublicApi(tester, OAuthTokensHandler.class, null);
    testPublicApi(tester, RevokingOAuthTokensHandler.class, null);
  }

  @Test
  void testServletsAndFilters() {
    var oidcProviderMetadata =
        new OIDCProviderMetadata(
            new Issuer("issuer"),
            List.of(SubjectType.PUBLIC),
            URI.create("https://example.com/jwks"));
    var clientAuthentication = new ClientSecretBasic(new ClientID(), new Secret());
    var configuration = new Configuration(oidcProviderMetadata, clientAuthentication);
    var tester =
        new NullPointerTester()
            .setDefault(Configuration.class, configuration)
            .setDefault(
                AuthenticationRedirector.class,
                new AuthenticationRedirector(configuration, "/callback"));
    testPublicApi(tester, UserFilter.class, null);
    testPublicApi(tester, CallbackServlet.class, null);
    testPublicApi(tester, LogoutCallbackServlet.class, null);
    testPublicApi(tester, BackchannelLogoutServlet.class, null);
    testPublicApi(tester, AbstractAuthorizationFilter.class, null);
    testPublicApi(tester, IsAuthenticatedFilter.class, null);
    testPublicApi(tester, HasRoleFilter.class, null);
  }

  @Test
  void testBackchannelLogoutSessionListener() {
    var tester = new NullPointerTester();
    testPublicApi(tester, BackchannelLogoutSessionListener.class, null);
  }

  @Test
  void testLoggedOutSessionStore() {
    var tester = new NullPointerTester();
    testPublicApi(tester, LoggedOutSessionStore.class, null);
    testPublicApi(tester, NullLoggedOutSessionStore.class, null);
    testPublicApi(tester, InMemoryLoggedOutSessionStore.class, null);
  }

  @Test
  void testUtils() {
    var tester = new NullPointerTester();
    testPublicApi(tester, Utils.class, null);
  }

  @Test
  void testJWTAuthorizationRequestHelper() throws Exception {
    var keyGenerator = new ECKeyGenerator(Curve.P_256);
    var key = keyGenerator.generate();
    var tester =
        new NullPointerTester()
            .setDefault(JWKGenerator.class, keyGenerator)
            .setDefault(JWK.class, key)
            .setDefault(JWSAlgorithm.class, JWSAlgorithm.ES256)
            .setDefault(
                AuthenticationRequest.class,
                new AuthenticationRequest(
                    URI.create("https://example.com/authorize"),
                    ResponseType.CODE,
                    new Scope(OIDCScopeValue.OPENID),
                    new ClientID("client"),
                    URI.create("https://example.com/callback"),
                    new State(),
                    new Nonce()))
            // @ForOverride method
            .ignore(
                JWTAuthorizationRequestHelper.class.getDeclaredMethod(
                    "maybeEncrypt", SignedJWT.class));
    testPublicApi(
        tester,
        JWTAuthorizationRequestHelper.class,
        new JWTAuthorizationRequestHelper() {
          @Override
          protected SignedJWT sign(JWTClaimsSet claimsSet) throws JOSEException {
            var jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), claimsSet);
            jwt.sign(new ECDSASigner(key));
            return jwt;
          }
        });
  }

  @Test
  void testPushedAuthorizationRequestHelper() {
    var oidcProviderMetadata =
        new OIDCProviderMetadata(
            new Issuer("issuer"),
            List.of(SubjectType.PUBLIC),
            URI.create("https://example.com/jwks"));
    oidcProviderMetadata.setPushedAuthorizationRequestEndpointURI(
        URI.create("https://example.com/par"));
    var clientAuthentication = new ClientSecretBasic(new ClientID(), new Secret());
    var configuration = new Configuration(oidcProviderMetadata, clientAuthentication);
    var tester =
        new NullPointerTester() //
            .setDefault(Configuration.class, configuration)
            .setDefault(
                AuthenticationRequest.class,
                new AuthenticationRequest(
                    URI.create("https://example.com/authorize"),
                    ResponseType.CODE,
                    new Scope(OIDCScopeValue.OPENID),
                    new ClientID("client"),
                    URI.create("https://example.com/callback"),
                    new State(),
                    new Nonce()));
    testPublicApi(
        tester,
        PushedAuthorizationRequestHelper.class,
        new PushedAuthorizationRequestHelper(
            configuration,
            new HTTPRequestSender() {
              @Override
              public ReadOnlyHTTPResponse send(ReadOnlyHTTPRequest httpRequest) throws IOException {
                return new PushedAuthorizationSuccessResponse(
                        URI.create("https://example.com/par/1337"), 42L)
                    .toHTTPResponse();
              }
            }));
  }
}
