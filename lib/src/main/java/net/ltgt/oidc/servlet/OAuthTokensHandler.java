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
