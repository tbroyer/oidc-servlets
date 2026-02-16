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

  /** Creates a {@link DPoPSupport} instance with the given private key and signature algorithm. */
  static DPoPSupport create(JWK key, JWSAlgorithm jwsAlgorithm) throws JOSEException {
    return create(new DefaultDPoPProofFactory(requireNonNull(key), requireNonNull(jwsAlgorithm)));
  }

  /**
   * Creates a {@link DPoPSupport} instance with the given private key, signature algorithm, and JCA
   * provider.
   */
  static DPoPSupport create(JWK key, JWSAlgorithm jwsAlgorithm, @Nullable Provider jcaProvider)
      throws JOSEException {
    return create(
        new DefaultDPoPProofFactory(
            requireNonNull(key), requireNonNull(jwsAlgorithm), jcaProvider));
  }

  /** Creates a {@link DPoPSupport} instance with the given DPoP proof factory. */
  static DPoPSupport create(DefaultDPoPProofFactory proofFactory) throws JOSEException {
    return create(
        requireNonNull(proofFactory), JWKThumbprintConfirmation.of(proofFactory.getPublicJWK()));
  }

  /**
   * Creates a {@link DPoPSupport} instance with the given DPoP proof factory and public key
   * thumbprint.
   */
  static DPoPSupport create(DPoPProofFactory proofFactory, JWKThumbprintConfirmation jkt) {
    requireNonNull(proofFactory);
    requireNonNull(jkt);
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
