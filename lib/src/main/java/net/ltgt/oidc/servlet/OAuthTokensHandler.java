package net.ltgt.oidc.servlet;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.token.Tokens;
import jakarta.servlet.http.HttpSession;

/**
 * Handles {@linkplain Tokens OAuth tokens} acquired at authentication time (by the {@link
 * CallbackServlet}) once they're no longer needed.
 *
 * <p>Tokens can be revoked immediately (default behavior if no specific {@link OAuthTokensHandler}
 * has been configured, through a {@link RevokingOAuthTokensHandler}), or stored in the session for
 * later use. In that case, it is your responsibility to revoke them, e.g. when the session is
 * destroyed.
 *
 * @see CallbackServlet
 * @see RevokingOAuthTokensHandler
 */
public interface OAuthTokensHandler {
  String CONTEXT_ATTRIBUTE_NAME = OAuthTokensHandler.class.getName();

  /**
   * Called by the {@link CallbackServlet} before it forgets about the tokens.
   *
   * @param tokenResponse The token response, containing the OAuth tokens and possibly some custom
   *     parameters
   */
  void tokensAcquired(AccessTokenResponse tokenResponse, HttpSession session);
}
