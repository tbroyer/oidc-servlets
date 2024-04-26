package net.ltgt.oidc.servlet;

import static java.util.Objects.requireNonNull;

import com.google.errorprone.annotations.ForOverride;
import com.google.errorprone.annotations.OverridingMethodsMustInvokeSuper;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Base class for filters that redirect to the OpenID Provider when the user is not authorized.
 *
 * <p>Requests that are authorized (and pass down the filter chain) are additionally marked with the
 * {@link #IS_PRIVATE_REQUEST_ATTRIBUTE_NAME} {@linkplain HttpServletRequest#getAttribute(String)
 * attribute}.
 *
 * <p>Subclasses should be installed <i>after</i> the {@link UserFilter}.
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect Core 1.0</a>
 * @see UserFilter
 */
public abstract class AbstractAuthorizationFilter extends HttpFilter {
  public static final String IS_PRIVATE_REQUEST_ATTRIBUTE_NAME =
      AbstractAuthorizationFilter.class.getName() + ".is_private";

  private AuthenticationRedirector authenticationRedirector;

  @OverridingMethodsMustInvokeSuper
  @Override
  public void init() throws ServletException {
    authenticationRedirector =
        (AuthenticationRedirector)
            getServletContext().getAttribute(AuthenticationRedirector.CONTEXT_ATTRIBUTE_NAME);
  }

  @ForOverride
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

  /**
   * Returns whether the user is authorized.
   *
   * <p>Implementations should only use the requests {@link HttpServletRequest#getUserPrincipal()
   * getUserPrincipal()} and/or {@link HttpServletRequest#isUserInRole(String) isUserInRole()}.
   */
  protected abstract boolean isAuthorized(HttpServletRequest req);

  /**
   * Returns whether the request targets a callback servlet, that should be exempted from
   * authorization check.
   */
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

  /**
   * This method is called whenever the user is not authorized and the request is a {@linkplain
   * Utils#isSafeMethod safe} {@linkplain Utils#isNavigation navigation} request.
   *
   * <p>The default implementation simply calls the globally configured {@link
   * AuthenticationRedirector}, and allows {@linkplain #configureAuthenticationRequest configuring
   * the authentication request}.
   *
   * <p>Subclasses can override this method to conditionally generate different responses.
   *
   * @see #configureAuthenticationRequest
   * @see HasRoleFilter
   * @see #sendUnauthorized
   */
  @ForOverride
  protected void redirectToAuthenticationEndpoint(HttpServletRequest req, HttpServletResponse res)
      throws IOException, ServletException {
    authenticationRedirector.redirectToAuthenticationEndpoint(
        req,
        res,
        Utils.getRequestUri(req),
        builder -> configureAuthenticationRequest(req, builder));
  }

  /**
   * Configures the authentication request when redirecting to the OpenID Provider.
   *
   * <p>This method is called by the {@link AuthenticationRedirector} called by {@link
   * #redirectToAuthenticationEndpoint}.
   *
   * @see #redirectToAuthenticationEndpoint
   */
  @ForOverride
  protected void configureAuthenticationRequest(
      HttpServletRequest req, AuthenticationRequest.Builder builder) {}

  /**
   * This method is called whenever is not authorized and the request is <b>not</b> a {@linkplain
   * Utils#isSafeMethod safe} {@linkplain Utils#isNavigation navigation} request.
   *
   * <p>The default implementation simply calls {@code res.sendError(SC_UNAUTHORIZED)}. This is not
   * strictly HTTP-compliant as it's missing the {@code WWW-Authenticate} response header, but is a
   * good way to signal the error to JavaScript clients making an AJAX request.
   *
   * @see #redirectToAuthenticationEndpoint
   * @see HasRoleFilter
   */
  @ForOverride
  protected void sendUnauthorized(HttpServletRequest req, HttpServletResponse res)
      throws IOException, ServletException {
    // XXX: this is not http-compliant as it's missing WWW-Authenticate
    res.sendError(HttpServletResponse.SC_UNAUTHORIZED);
  }
}
