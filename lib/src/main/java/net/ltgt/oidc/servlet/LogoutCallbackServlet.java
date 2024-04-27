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
            .map(session -> (LogoutState) session.getAttribute(LogoutState.SESSION_ATTRIBUTE_NAME))
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
