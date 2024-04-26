package net.ltgt.oidc.servlet;

import com.google.errorprone.annotations.ForOverride;
import com.google.errorprone.annotations.OverridingMethodsMustInvokeSuper;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * This servlet starts the authentication workflow and redirects back to a given URL afterward.
 *
 * <p>The target page is given in the {@link Utils#RETURN_TO_PARAMETER_NAME} request parameter. It
 * should be given as an absolute path (possibly with a query string), though a full URL would be
 * accepted as long as it's the same <a
 * href="https://datatracker.ietf.org/doc/html/rfc6454">origin</a>.
 */
public class LoginServlet extends HttpServlet {
  private AuthenticationRedirector authenticationRedirector;

  @OverridingMethodsMustInvokeSuper
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
    authenticationRedirector.redirectToAuthenticationEndpoint(
        req, resp, returnTo, builder -> configureAuthenticationRequest(req, builder));
  }

  /** Configures the authentication request when redirecting to the OpenID Provider. */
  @ForOverride
  protected void configureAuthenticationRequest(
      HttpServletRequest req, AuthenticationRequest.Builder builder) {}
}
