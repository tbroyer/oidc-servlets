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

import com.google.errorprone.annotations.concurrent.LazyInit;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.oauth2.sdk.dpop.DPoPProofFactory;
import com.nimbusds.oauth2.sdk.dpop.DefaultDPoPProofFactory;
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;
import jakarta.servlet.http.HttpSession;
import java.io.Serial;
import java.io.Serializable;
import java.security.Provider;
import org.jspecify.annotations.Nullable;

/** Base implementation of {@link DPoPSupport} that generates a private key per session. */
public abstract class PerSessionDPoPSupport implements DPoPSupport {

  private final JWSAlgorithm jwsAlgorithm;
  private final @Nullable Provider jcaProvider;

  /** Constructs an instance with the given signature algorithm, and no JCA provider. */
  protected PerSessionDPoPSupport(JWSAlgorithm jwsAlgorithm) {
    this(jwsAlgorithm, null);
  }

  /** Constructs an instance with the given signature algorithm and optional JCA provider. */
  protected PerSessionDPoPSupport(JWSAlgorithm jwsAlgorithm, @Nullable Provider jcaProvider) {
    this.jwsAlgorithm = requireNonNull(jwsAlgorithm);
    this.jcaProvider = jcaProvider;
  }

  @Override
  public DPoPProofFactory getProofFactory(HttpSession session) {
    return ensureSessionData(session).getProofFactory(jcaProvider);
  }

  @Override
  public JWKThumbprintConfirmation getJWKThumbprintConfirmation(HttpSession session) {
    return ensureSessionData(session).getJWKThumbprintConfirmation(jcaProvider);
  }

  /**
   * Returns a private key to be associated to a session.
   *
   * <p>The key must have a type and curve compatible with the algorithm given to the constructor,
   * and must be usable for signing.
   */
  protected abstract JWK generatePrivateKey() throws JOSEException;

  private DPoPSessionData ensureSessionData(HttpSession session) {
    var sessionData =
        (DPoPSessionData) session.getAttribute(DPoPSessionData.SESSION_ATTRIBUTE_NAME);
    if (sessionData == null) {
      try {
        sessionData = new DPoPSessionData(generatePrivateKey(), jwsAlgorithm);
      } catch (JOSEException e) {
        throw new RuntimeException(e);
      }
      session.setAttribute(DPoPSessionData.SESSION_ATTRIBUTE_NAME, sessionData);
    }
    return sessionData;
  }

  // @VisibleForTesting
  static final class DPoPSessionData implements Serializable {
    static final String SESSION_ATTRIBUTE_NAME = DPoPSessionData.class.getName();

    @Serial private static final long serialVersionUID = 0L;

    final JWK key;
    final JWSAlgorithm jwsAlgorithm;
    @LazyInit private transient volatile DefaultDPoPProofFactory proofFactory;
    @LazyInit private transient volatile JWKThumbprintConfirmation jkt;

    DPoPSessionData(JWK key, JWSAlgorithm jwsAlgorithm) {
      this.key = key;
      this.jwsAlgorithm = jwsAlgorithm;
    }

    DefaultDPoPProofFactory getProofFactory(@Nullable Provider jcaProvider) {
      ensureProofFactory(jcaProvider);
      return proofFactory;
    }

    JWKThumbprintConfirmation getJWKThumbprintConfirmation(@Nullable Provider jcaProvider) {
      ensureProofFactory(jcaProvider);
      return jkt;
    }

    private void ensureProofFactory(@Nullable Provider jcaProvider) {
      var proofFactory = this.proofFactory;
      if (proofFactory == null) {
        synchronized (this) {
          proofFactory = this.proofFactory;
          if (proofFactory == null) {
            try {
              proofFactory = new DefaultDPoPProofFactory(key, jwsAlgorithm, jcaProvider);
              jkt = JWKThumbprintConfirmation.of(proofFactory.getPublicJWK());
            } catch (JOSEException e) {
              throw new RuntimeException(e);
            }
            this.proofFactory = proofFactory;
          }
        }
      }
    }
  }
}
