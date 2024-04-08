package net.ltgt.oidc.servlet.example.jetty;

import com.google.errorprone.annotations.ForOverride;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

public abstract class AbstractAuthorizationFilter extends HttpFilter {
  private AuthenticationRedirector authenticationRedirector;

  @Override
  public void init() throws ServletException {
    authenticationRedirector =
        (AuthenticationRedirector)
            getServletContext().getAttribute(AuthenticationRedirector.CONTEXT_ATTRIBUTE_NAME);
  }

  @Override
  protected void doFilter(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
      throws IOException, ServletException {
    if (isAuthorized(req)
        || req.getRequestURI().equals(authenticationRedirector.getCallbackPath())) {
      super.doFilter(req, res, chain);
      return;
    }
    if (Utils.isNavigation(req) && Utils.isSafeMethod(req)) {
      redirectToAuthenticationEndpoint(req, res);
      return;
    }
    sendUnauthorized(req, res);
  }

  protected abstract boolean isAuthorized(HttpServletRequest req);

  @ForOverride
  protected void redirectToAuthenticationEndpoint(HttpServletRequest req, HttpServletResponse res)
      throws IOException, ServletException {
    authenticationRedirector.redirectToAuthenticationEndpoint(req, res, Utils.getRequestUri(req));
  }

  @ForOverride
  protected void sendUnauthorized(HttpServletRequest req, HttpServletResponse res)
      throws IOException, ServletException {
    // XXX: this is not http-compliant as it's missing WWW-Authenticate
    res.sendError(HttpServletResponse.SC_UNAUTHORIZED);
  }
}
