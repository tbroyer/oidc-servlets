package net.ltgt.oidc.servlet;

import static java.util.Objects.requireNonNull;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.oauth2.sdk.dpop.DPoPProofFactory;
import com.nimbusds.oauth2.sdk.dpop.DefaultDPoPProofFactory;
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;
import jakarta.servlet.http.HttpSession;
import java.security.Provider;
import org.jspecify.annotations.Nullable;

/**
 * Contains the objects necessary to support (and use) DPoP.
 *
 * <p>An instance of this class needs to be registered as a {@link jakarta.servlet.ServletContext
 * ServletContext} attribute under the name {@link #CONTEXT_ATTRIBUTE_NAME}, and ideally also passed
 * to the {@link AuthenticationRedirector#AuthenticationRedirector(Configuration, String,
 * DPoPSupport) AuthenticationRedirector} constructor for improved security (end-to-end binding of
 * the entire authentication flow).
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9449">OAuth 2.0 Demonstrating Proof of
 *     Possession (DPoP)</a>
 */
public interface DPoPSupport {
  String CONTEXT_ATTRIBUTE_NAME = DPoPSupport.class.getName();

  static DPoPSupport create(JWK key, JWSAlgorithm jwsAlgorithm) throws JOSEException {
    return create(new DefaultDPoPProofFactory(key, jwsAlgorithm));
  }

  static DPoPSupport create(JWK key, JWSAlgorithm jwsAlgorithm, @Nullable Provider jcaProvider)
      throws JOSEException {
    return create(new DefaultDPoPProofFactory(key, jwsAlgorithm, jcaProvider));
  }

  static DPoPSupport create(DefaultDPoPProofFactory proofFactory) throws JOSEException {
    return create(
        requireNonNull(proofFactory), JWKThumbprintConfirmation.of(proofFactory.getPublicJWK()));
  }

  static DPoPSupport create(DPoPProofFactory proofFactory, JWKThumbprintConfirmation jkt) {
    return new DPoPSupport() {
      @Override
      public DPoPProofFactory getProofFactory(HttpSession session) {
        return proofFactory;
      }

      @Override
      public JWKThumbprintConfirmation getJWKThumbprintConfirmation(HttpSession session) {
        return jkt;
      }
    };
  }

  DPoPProofFactory getProofFactory(HttpSession session);

  JWKThumbprintConfirmation getJWKThumbprintConfirmation(HttpSession session);
}
