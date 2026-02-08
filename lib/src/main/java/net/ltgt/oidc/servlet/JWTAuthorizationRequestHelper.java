package net.ltgt.oidc.servlet;

import static java.util.Objects.requireNonNull;

import com.google.errorprone.annotations.ForOverride;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import java.net.URI;
import java.security.Provider;
import java.util.function.Consumer;
import org.jspecify.annotations.Nullable;

/**
 * Helps implement JWT-secured authorization requests.
 *
 * <p>Override {@link AuthenticationRedirector#sendRedirect(AuthenticationRequest, Consumer)} to
 * call {@link #sendRedirect(AuthenticationRequest, Consumer)} to secure the authentication request
 * in a JWT.
 *
 * {@snippet lang=java :
 * servletContext.setAttribute(
 *     AuthenticationRedirector.CONTEXT_ATTRIBUTE_NAME,
 *     new AuthenticationRedirector(configuration, callbackPath) {
 *       private final JWTAuthorizationRequestHelper jarHelper = JWTAuthorizationRequestHelper.create(jwk, jwsAlg);
 *
 *       @Override
 *       public void sendRedirect(AuthenticationRequest authenticationRequest, Consumer<URI> sendRedirect) {
 *         jarHelper.sendRedirect(authenticationRequest, sendRedirect);
 *       }
 *     });
 * }
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9101">The OAuth 2.0 Authorization
 *     Framework: JWT-Secured Authorization Request (JAR)</a>
 */
public abstract class JWTAuthorizationRequestHelper {
  public static final JOSEObjectType TYPE = new JOSEObjectType("oauth-authz-req+jwt");

  /**
   * Creates a helper to sign the JWT with the given key and algorithm.
   *
   * <p>This is equivalent to {@code new JWTAuthorizationRequestHelper(jwk, jwsAlg, null)}.
   */
  public static JWTAuthorizationRequestHelper create(JWK jwk, JWSAlgorithm jwsAlg)
      throws JOSEException {
    return create(jwk, jwsAlg, null);
  }

  /** Creates a helper to sign the JWT with the given key, algorithm and JCA provider. */
  public static JWTAuthorizationRequestHelper create(
      JWK jwk, JWSAlgorithm jwsAlg, @Nullable Provider jcaProvider) throws JOSEException {
    var factory = new DefaultJWSSignerFactory();
    if (jcaProvider != null) {
      factory.getJCAContext().setProvider(jcaProvider);
    }
    var jwsSigner = factory.createJWSSigner(requireNonNull(jwk), requireNonNull(jwsAlg));

    return new JWTAuthorizationRequestHelper() {
      @Override
      protected SignedJWT sign(JWTClaimsSet claimsSet) throws JOSEException {
        var jar =
            new SignedJWT(
                new JWSHeader.Builder(jwsAlg).type(TYPE).keyID(jwk.getKeyID()).build(), claimsSet);
        jar.sign(jwsSigner);
        return jar;
      }
    };
  }

  public void sendRedirect(
      AuthenticationRequest authenticationRequest, Consumer<URI> sendRedirect) {
    try {
      sendRedirect.accept(
          new AuthenticationRequest.Builder(
                  maybeEncrypt(sign(authenticationRequest.toJWTClaimsSet())),
                  authenticationRequest.getClientID())
              .endpointURI(authenticationRequest.getEndpointURI())
              .build()
              .toURI());
    } catch (JOSEException e) {
      throw new RuntimeException(e);
    }
  }

  /** Signs the given JWT claims set to create the request's JWT. */
  protected abstract SignedJWT sign(JWTClaimsSet claimsSet) throws JOSEException;

  /**
   * Possibly encrypts the signed JWT into a nested JWT.
   *
   * @implSpec The default implementation returns the signed JWT as-is, without additionally
   *     encrypting it.
   */
  @ForOverride
  protected JWT maybeEncrypt(SignedJWT signed) throws JOSEException {
    return signed;
  }
}
