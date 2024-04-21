/*
 * Copyright 2012-2016, Connect2id Ltd and contributors.
 * Copyright 2024, Thomas Broyer
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package net.ltgt.oidc.servlet;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jwt.*;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.claims.LogoutTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.validators.AbstractJWTValidator;
import com.nimbusds.openid.connect.sdk.validators.LogoutTokenClaimsVerifier;
import java.net.URL;
import net.jcip.annotations.ThreadSafe;
import org.checkerframework.checker.nullness.qual.Nullable;

/**
 * Validator of logout tokens issued by an OpenID Provider (OP).
 *
 * <p>Supports processing of logout tokens with the following protection:
 *
 * <ul>
 *   <li>Logout tokens signed (JWS) with the OP's RSA or EC key, require the OP public JWK set
 *       (provided by value or URL) to verify them.
 *   <li>Logout tokens authenticated with a JWS HMAC, require the client's secret to verify them.
 * </ul>
 *
 * <p>The logout types may be {@linkplain #TYPE explicitly typed} with {@code logout+jwt}.
 *
 * <p>Related specifications:
 *
 * <ul>
 *   <li>OpenID Connect Back-Channel Logout 1.0, section 2.4 (draft 07).
 * </ul>
 *
 * <p>This is a fork of Nimbus' {@link
 * com.nimbusds.openid.connect.sdk.validators.LogoutTokenValidator LogoutTokenValidator} that
 * loosens the type validation to allow {@link JOSEObjectType#JWT jwt} in addition to {@link #TYPE
 * logout+jwt} whenever the token is not required to be explicitly typed.
 */
@ThreadSafe
class LogoutTokenValidator extends AbstractJWTValidator {

  /** The recommended logout token JWT (typ) type. */
  public static final JOSEObjectType TYPE = new JOSEObjectType("logout+jwt");

  /**
   * {@code true} to require logout tokens to be explicitly {@link #TYPE typed}, {@code false} to
   * accept untyped tokens.
   */
  private final boolean requireTypedTokens;

  /**
   * Creates a new validator for RSA or EC signed logout tokens where the OpenID Provider's JWK set
   * is specified by value. Explicit typing of the logout tokens is not required but wil be checked
   * if present.
   *
   * @param expectedIssuer The expected logout token issuer (OpenID Provider). Must not be {@code
   *     null}.
   * @param clientID The client ID. Must not be {@code null}.
   * @param expectedJWSAlg The expected RSA or EC JWS algorithm. Must not be {@code null}.
   * @param jwkSet The OpenID Provider JWK set. Must not be {@code null}.
   */
  public LogoutTokenValidator(
      final Issuer expectedIssuer,
      final ClientID clientID,
      final JWSAlgorithm expectedJWSAlg,
      final JWKSet jwkSet) {

    this(
        expectedIssuer,
        clientID,
        new JWSVerificationKeySelector<>(expectedJWSAlg, new ImmutableJWKSet<>(jwkSet)),
        null);
  }

  /**
   * Creates a new validator for RSA or EC signed logout tokens where the OpenID Provider's JWK set
   * is specified by URL. Explicit typing of the logout tokens is not required but wil be checked if
   * present.
   *
   * @param expectedIssuer The expected logout token issuer (OpenID Provider). Must not be {@code
   *     null}.
   * @param clientID The client ID. Must not be {@code null}.
   * @param expectedJWSAlg The expected RSA or EC JWS algorithm. Must not be {@code null}.
   * @param jwkSetURI The OpenID Provider JWK set URL. Must not be {@code null}.
   */
  public LogoutTokenValidator(
      final Issuer expectedIssuer,
      final ClientID clientID,
      final JWSAlgorithm expectedJWSAlg,
      final URL jwkSetURI) {

    this(expectedIssuer, clientID, expectedJWSAlg, jwkSetURI, null);
  }

  /**
   * Creates a new validator for RSA or EC signed logout tokens where the OpenID Provider's JWK set
   * is specified by URL. Permits setting of a specific resource retriever (HTTP client) for the JWK
   * set. Explicit typing of the logout tokens is not required but wil be checked if present.
   *
   * @param expectedIssuer The expected logout token issuer (OpenID Provider). Must not be {@code
   *     null}.
   * @param clientID The client ID. Must not be {@code null}.
   * @param expectedJWSAlg The expected RSA or EC JWS algorithm. Must not be {@code null}.
   * @param jwkSetURI The OpenID Provider JWK set URL. Must not be {@code null}.
   * @param resourceRetriever For retrieving the OpenID Connect Provider JWK set from the specified
   *     URL. If {@code null} the {@link com.nimbusds.jose.util.DefaultResourceRetriever default
   *     retriever} will be used, with preset HTTP connect timeout, HTTP read timeout and entity
   *     size limit.
   */
  @SuppressWarnings("deprecation")
  public LogoutTokenValidator(
      final Issuer expectedIssuer,
      final ClientID clientID,
      final JWSAlgorithm expectedJWSAlg,
      final URL jwkSetURI,
      final @Nullable ResourceRetriever resourceRetriever) {

    this(
        expectedIssuer,
        clientID,
        new JWSVerificationKeySelector<>(
            expectedJWSAlg, new RemoteJWKSet<>(jwkSetURI, resourceRetriever)),
        null);
  }

  /**
   * Creates a new validator for HMAC protected logout tokens. Explicit typing of the logout tokens
   * is not required but wil be checked if present.
   *
   * @param expectedIssuer The expected logout token issuer (OpenID Provider). Must not be {@code
   *     null}.
   * @param clientID The client ID. Must not be {@code null}.
   * @param expectedJWSAlg The expected HMAC JWS algorithm. Must not be {@code null}.
   * @param clientSecret The client secret. Must not be {@code null}.
   */
  public LogoutTokenValidator(
      final Issuer expectedIssuer,
      final ClientID clientID,
      final JWSAlgorithm expectedJWSAlg,
      final Secret clientSecret) {

    this(
        expectedIssuer,
        clientID,
        new JWSVerificationKeySelector<>(
            expectedJWSAlg, new ImmutableSecret<>(clientSecret.getValueBytes())),
        null);
  }

  /**
   * Creates a new logout token validator.
   *
   * @param expectedIssuer The expected logout token issuer (OpenID Provider). Must not be {@code
   *     null}.
   * @param clientID The client ID. Must not be {@code null}.
   * @param jwsKeySelector The key selector for JWS verification, {@code null} if unsecured (plain)
   *     logout tokens are expected.
   * @param jweKeySelector The key selector for JWE decryption, {@code null} if encrypted logout
   *     tokens are not expected.
   */
  @SuppressWarnings("InlineMeSuggester")
  @Deprecated
  public LogoutTokenValidator(
      final Issuer expectedIssuer,
      final ClientID clientID,
      final @Nullable JWSKeySelector<?> jwsKeySelector,
      final @Nullable JWEKeySelector<?> jweKeySelector) {

    this(expectedIssuer, clientID, false, jwsKeySelector, jweKeySelector);
  }

  /**
   * Creates a new logout token validator.
   *
   * @param expectedIssuer The expected logout token issuer (OpenID Provider). Must not be {@code
   *     null}.
   * @param clientID The client ID. Must not be {@code null}.
   * @param requireTypedToken {@code true} to require logout tokens to be explicitly {@link #TYPE
   *     typed}, {@code false} to accept untyped tokens.
   * @param jwsKeySelector The key selector for JWS verification, {@code null} if unsecured (plain)
   *     logout tokens are expected.
   * @param jweKeySelector The key selector for JWE decryption, {@code null} if encrypted logout
   *     tokens are not expected.
   */
  public LogoutTokenValidator(
      final Issuer expectedIssuer,
      final ClientID clientID,
      final boolean requireTypedToken,
      final @Nullable JWSKeySelector<?> jwsKeySelector,
      final @Nullable JWEKeySelector<?> jweKeySelector) {

    super(TYPE, expectedIssuer, clientID, jwsKeySelector, jweKeySelector);
    this.requireTypedTokens = requireTypedToken;
  }

  /**
   * Validates the specified logout token.
   *
   * @param logoutToken The logout token. Must not be {@code null}.
   * @return The claims set of the verified logout token.
   * @throws BadJOSEException If the logout token is invalid or expired.
   * @throws JOSEException If an internal JOSE exception was encountered.
   */
  public LogoutTokenClaimsSet validate(final JWT logoutToken)
      throws BadJOSEException, JOSEException {

    if (logoutToken instanceof PlainJWT) {
      throw new BadJWTException("Unsecured (plain) logout tokens are illegal");
    } else if (logoutToken instanceof SignedJWT) {
      return validate((SignedJWT) logoutToken);
    } else if (logoutToken instanceof EncryptedJWT) {
      return validate((EncryptedJWT) logoutToken);
    } else {
      throw new JOSEException("Unexpected JWT type: " + logoutToken.getClass());
    }
  }

  /**
   * Verifies the specified signed logout token.
   *
   * @param logoutToken The logout token. Must not be {@code null}.
   * @return The claims set of the verified logout token.
   * @throws BadJOSEException If the logout token is invalid or expired.
   * @throws JOSEException If an internal JOSE exception was encountered.
   */
  @SuppressWarnings("unchecked")
  private LogoutTokenClaimsSet validate(final SignedJWT logoutToken)
      throws BadJOSEException, JOSEException {

    if (getJWSKeySelector() == null) {
      throw new BadJWTException("Verification of signed JWTs not configured");
    }

    ConfigurableJWTProcessor<?> jwtProcessor = new DefaultJWTProcessor<>();
    jwtProcessor.setJWSTypeVerifier(new TypeVerifier(requireTypedTokens));
    jwtProcessor.setJWSKeySelector(getJWSKeySelector());
    jwtProcessor.setJWTClaimsSetVerifier(
        new LogoutTokenClaimsVerifier(getExpectedIssuer(), getClientID()));
    JWTClaimsSet jwtClaimsSet = jwtProcessor.process(logoutToken, null);
    return toLogoutTokenClaimsSet(jwtClaimsSet);
  }

  /**
   * Verifies the specified signed and encrypted logout token.
   *
   * @param logoutToken The logout token. Must not be {@code null}.
   * @return The claims set of the verified logout token.
   * @throws BadJOSEException If the logout token is invalid or expired.
   * @throws JOSEException If an internal JOSE exception was encountered.
   */
  @SuppressWarnings("unchecked")
  private LogoutTokenClaimsSet validate(final EncryptedJWT logoutToken)
      throws BadJOSEException, JOSEException {

    if (getJWEKeySelector() == null) {
      throw new BadJWTException("Decryption of JWTs not configured");
    }
    if (getJWSKeySelector() == null) {
      throw new BadJWTException("Verification of signed JWTs not configured");
    }

    ConfigurableJWTProcessor<?> jwtProcessor = new DefaultJWTProcessor<>();
    jwtProcessor.setJWETypeVerifier(new TypeVerifier(requireTypedTokens));
    jwtProcessor.setJWSKeySelector(getJWSKeySelector());
    jwtProcessor.setJWEKeySelector(getJWEKeySelector());
    jwtProcessor.setJWTClaimsSetVerifier(
        new LogoutTokenClaimsVerifier(getExpectedIssuer(), getClientID()));
    JWTClaimsSet jwtClaimsSet = jwtProcessor.process(logoutToken, null);

    return toLogoutTokenClaimsSet(jwtClaimsSet);
  }

  @SuppressWarnings("rawtypes")
  private static class TypeVerifier implements JOSEObjectTypeVerifier {

    private final boolean requireTypedTokens;

    public TypeVerifier(final boolean requireTypedTokens) {
      this.requireTypedTokens = requireTypedTokens;
    }

    @Override
    public void verify(final JOSEObjectType type, final SecurityContext context)
        throws BadJOSEException {

      if (requireTypedTokens) {
        if (!TYPE.equals(type)) {
          throw new BadJOSEException(
              "Invalid / missing logout token typ (type) header, must be " + TYPE);
        }
      } else {
        if (type != null && !TYPE.equals(type) && !JOSEObjectType.JWT.equals(type)) {
          throw new BadJOSEException("If set the logout token typ (type) header must be " + TYPE);
        }
      }
    }
  }

  /**
   * Converts a JWT claims set to a logout token claims set.
   *
   * @param jwtClaimsSet The JWT claims set. Must not be {@code null}.
   * @return The logout token claims set.
   * @throws JOSEException If conversion failed.
   */
  private static LogoutTokenClaimsSet toLogoutTokenClaimsSet(final JWTClaimsSet jwtClaimsSet)
      throws JOSEException {

    try {
      return new LogoutTokenClaimsSet(jwtClaimsSet);
    } catch (ParseException e) {
      // Claims set must be verified at this point
      throw new JOSEException(e.getMessage(), e);
    }
  }
}
