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
