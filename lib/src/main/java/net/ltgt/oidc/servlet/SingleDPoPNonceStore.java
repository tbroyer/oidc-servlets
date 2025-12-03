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
