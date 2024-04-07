package net.ltgt.oidc.servlet.example.jetty;

import com.nimbusds.openid.connect.sdk.LogoutRequest;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

public class LogoutServlet extends HttpServlet {
  private Configuration configuration;

  @Override
  public void init() throws ServletException {
    configuration =
        (Configuration) getServletContext().getAttribute(Configuration.CONTEXT_ATTRIBUTE_NAME);
  }

  // XXX: what to do on GET? show interstitial?

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException, IOException {
    if (!Utils.isNavigation(req)) {
      resp.sendError(HttpServletResponse.SC_BAD_REQUEST);
      return;
    }
    // XXX: prevent CSRF with synchronizer token pattern? off-load to a filter? (OWASP CSRFGuard?)
    // XXX: what to do with CSRF? redirect? show interstitial? (fallback to doGet) send error?
    if (!Utils.isSameOrigin(req)) {
      Utils.sendRedirect(resp, "/");
      return;
    }

    var session = req.getSession(false);
    if (session == null) {
      Utils.sendRedirect(resp, "/");
      return;
    }
    var sessionInfo = (SessionInfo) session.getAttribute(SessionInfo.SESSION_ATTRIBUTE_NAME);
    session.invalidate();
    if (sessionInfo == null) {
      Utils.sendRedirect(resp, "/");
      return;
    }

    var logoutRequest =
        new LogoutRequest(
            configuration.providerMetadata().getEndSessionEndpointURI(),
            sessionInfo.oidcTokens().getIDToken());
    Utils.sendRedirect(resp, logoutRequest.toURI().toASCIIString());
  }
}
