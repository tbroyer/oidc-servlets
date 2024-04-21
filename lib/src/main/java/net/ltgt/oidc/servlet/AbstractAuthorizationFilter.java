package net.ltgt.oidc.servlet;

import static java.util.Objects.requireNonNull;

import com.google.errorprone.annotations.ForOverride;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

public abstract class AbstractAuthorizationFilter extends HttpFilter {
  public static final String IS_PRIVATE_REQUEST_ATTRIBUTE_NAME =
      AbstractAuthorizationFilter.class.getName() + ".is_private";

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
    if (isAuthorized(req) || isCallbackServlet(req)) {
      req.setAttribute(IS_PRIVATE_REQUEST_ATTRIBUTE_NAME, true);
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
  protected boolean isCallbackServlet(HttpServletRequest req) {
    Class<?> servletClass;
    try {
      servletClass =
          Class.forName(
              requireNonNull(
                      req.getServletContext()
                          .getServletRegistrations()
                          .get(req.getHttpServletMapping().getServletName()))
                  .getClassName(),
              false,
              Thread.currentThread().getContextClassLoader());
    } catch (ClassNotFoundException e) {
      // This should not happen as servlet class should have already been validated by the container
      throw new AssertionError(e);
    }
    return CallbackServlet.class.isAssignableFrom(servletClass)
        || BackchannelLogoutServlet.class.isAssignableFrom(servletClass);
  }

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
