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

import com.nimbusds.openid.connect.sdk.Nonce;
import java.net.URI;
import org.jspecify.annotations.Nullable;

/**
 * Implements a {@link DPoPNonceStore} that stores a single nonce, shared for all URIs.
 *
 * <p>This can be used as an optimization (over the default {@link PerUriDPoPNonceStore}) when you
 * don't otherwise use the OAuth access tokens and know the Token Endpoint and User Info Endpoint
 * share the same nonce.
 */
public class SingleDPoPNonceStore implements DPoPNonceStore {
  private volatile @Nullable Nonce nonce;

  /** Gets the last stored nonce, irrespective of the given URI. */
  @Override
  public @Nullable Nonce getNonce(URI uri) {
    return nonce;
  }

  /** Stores the given nonce, irrespective of the URI. */
  @Override
  public void setNonce(URI uri, Nonce nonce) {
    this.nonce = nonce;
  }
}
