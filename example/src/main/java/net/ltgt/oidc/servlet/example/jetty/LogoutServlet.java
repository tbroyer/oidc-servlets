package net.ltgt.oidc.servlet.example.jetty;

import com.nimbusds.openid.connect.sdk.LogoutRequest;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;

public class LogoutServlet extends HttpServlet {
  private static final String REDIRECT_BACK_AFTER_LOGOUT = "redirect-back-after-logout";

  private Configuration configuration;
  private Boolean redirectBackAfterLogout;

  public LogoutServlet() {}

  public LogoutServlet(boolean redirectBackAfterLogout) {
    this.redirectBackAfterLogout = redirectBackAfterLogout;
  }

  @Override
  public void init() throws ServletException {
    configuration =
        (Configuration) getServletContext().getAttribute(Configuration.CONTEXT_ATTRIBUTE_NAME);
    if (redirectBackAfterLogout == null) {
      this.redirectBackAfterLogout =
          Boolean.parseBoolean(getInitParameter(REDIRECT_BACK_AFTER_LOGOUT));
    }
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

    // TODO: get a dynamic redirection URI as request parameter (need to validate its value),
    //       and use a specific logout callback URI; on return from OP, redirect to the stored URI.
    //       Maybe use a state in addition then (to be checked in the logout callback URI)
    var logoutRequest =
        new LogoutRequest(
            configuration.providerMetadata().getEndSessionEndpointURI(),
            sessionInfo.oidcTokens().getIDToken(),
            redirectBackAfterLogout
                ? URI.create(req.getRequestURL().toString()).resolve("/")
                : null,
            null);
    Utils.sendRedirect(resp, logoutRequest.toURI().toASCIIString());
  }
}
