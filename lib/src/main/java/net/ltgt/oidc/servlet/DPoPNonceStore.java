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
 * Stores the DPoP nonces sent by the servers.
 *
 * <p>It's up to the implementations to decide the granularity of the nonces ({@linkplain
 * PerUriDPoPNonceStore per URI}, per origin, a {@linkplain SingleDPoPNonceStore single nonce}
 * shared for all URIs, or something more specific).
 *
 * @see PerUriDPoPNonceStore
 * @see SingleDPoPNonceStore
 */
public interface DPoPNonceStore {
  String CONTEXT_ATTRIBUTE_NAME = DPoPNonceStore.class.getName();

  /** Gets the last stored nonce for the given URI. */
  @Nullable Nonce getNonce(URI uri);

  /** Stores a nonce for a given URI. */
  void setNonce(URI uri, Nonce nonce);
}
