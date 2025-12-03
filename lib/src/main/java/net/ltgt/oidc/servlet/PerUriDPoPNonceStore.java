package net.ltgt.oidc.servlet;

import com.nimbusds.openid.connect.sdk.Nonce;
import java.net.URI;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.jspecify.annotations.Nullable;

/**
 * Implements a {@link DPoPNonceStore} where nonces are stored with per-URI granularity.
 *
 * <p>This means that, for instance, the nonce for the Token Endpoint is not reused for the User
 * Info Endpoint, which will be suboptimal if you know upfront that they'll share their nonces, in
 * which case the {@link SingleDPoPNonceStore} or another implementation tailored to your use case
 * would be more appropriate.
 *
 * <p>This is the default implementation if no specific nonce store is configured in the servlet
 * context, as it's deemed the best compromise for performance (stores nonces to avoid always going
 * through a {@code use_dpop_nonce} error, but does not store a single nonce in case the Token and
 * User Info endpoints use different nonces).
 */
public class PerUriDPoPNonceStore implements DPoPNonceStore {
  private final ConcurrentMap<URI, Nonce> nonces = new ConcurrentHashMap<>(2);

  @Override
  public @Nullable Nonce getNonce(URI uri) {
    return nonces.get(uri);
  }

  @Override
  public void setNonce(URI uri, Nonce nonce) {
    nonces.put(uri, nonce);
  }
}
