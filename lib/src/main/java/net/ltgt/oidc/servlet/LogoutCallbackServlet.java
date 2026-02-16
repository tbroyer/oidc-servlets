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

import com.nimbusds.oauth2.sdk.id.State;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;
import java.util.Optional;

/**
 * Implements a post-logout redirect URI for use with <a
 * href="https://openid.net/specs/openid-connect-rpinitiated-1_0.html">OpenID Connect RP-Initiated
 * Logout</a>
 *
 * <p>Logout state must have been put in the {@linkplain jakarta.servlet.http.HttpSession session}
 * by the {@link LogoutServlet}.
 *
 * <p>After validating the request, the user will be redirected to the page stored in the logout
 * state.
 *
 * @see <a href="https://openid.net/specs/openid-connect-rpinitiated-1_0.html">OpenID Connect
 *     RP-Initiated Logout 1.0</a>
 */
public class LogoutCallbackServlet extends HttpServlet {
  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException, IOException {
    doPost(req, resp);
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException, IOException {
    if (!Utils.isNavigation(req)) {
      resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "Not a navigation request");
    }
    var stateParam = State.parse(req.getParameter("state"));
    var logoutState =
        Optional.ofNullable(req.getSession(false))
            .map(
                session -> {
                  var state =
                      (LogoutState) session.getAttribute(LogoutState.SESSION_ATTRIBUTE_NAME);
                  session.removeAttribute(LogoutState.SESSION_ATTRIBUTE_NAME);
                  return state;
                })
            .orElse(null);
    if (logoutState == null) {
      // XXX: redirect to home page instead?
      resp.sendError(
          HttpServletResponse.SC_BAD_REQUEST, "Missing saved state from logout request initiation");
      return;
    }
    if (!Objects.equals(stateParam, logoutState.state())) {
      // XXX: redirect to home page instead?
      resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "State mismatch");
      return;
    }
    Utils.sendRedirect(resp, logoutState.requestUri());
  }
}
