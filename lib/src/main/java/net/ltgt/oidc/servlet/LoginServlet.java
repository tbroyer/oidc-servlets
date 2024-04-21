package net.ltgt.oidc.servlet;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

public class LoginServlet extends HttpServlet {
  private AuthenticationRedirector authenticationRedirector;

  @Override
  public void init() throws ServletException {
    authenticationRedirector =
        (AuthenticationRedirector)
            getServletContext().getAttribute(AuthenticationRedirector.CONTEXT_ATTRIBUTE_NAME);
  }

  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException, IOException {
    doPost(req, resp);
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException, IOException {
    if (!Utils.isNavigation(req)) {
      resp.sendError(HttpServletResponse.SC_BAD_REQUEST);
      return;
    }
    var returnTo = Utils.getReturnToParameter(req);
    // XXX: prevent CSRF with synchronizer token pattern? off-load to a filter? (OWASP CSRFGuard?)
    // XXX: what to do with CSRF? redirect? show interstitial? (fallback to doGet) send error?
    if (!Utils.isSameOrigin(req)) {
      Utils.sendRedirect(resp, returnTo);
      return;
    }
    if (req.getUserPrincipal() != null) {
      Utils.sendRedirect(resp, returnTo);
      return;
    }
    authenticationRedirector.redirectToAuthenticationEndpoint(req, resp, returnTo);
  }
}
