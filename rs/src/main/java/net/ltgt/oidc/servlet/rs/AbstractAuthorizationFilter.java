package net.ltgt.oidc.servlet.rs;

import com.google.errorprone.annotations.ForOverride;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import jakarta.annotation.Priority;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;
import java.io.IOException;

@Priority(Priorities.AUTHORIZATION)
public abstract class AbstractAuthorizationFilter implements ContainerRequestFilter {
  public static final String IS_PRIVATE_PROPERTY_NAME =
      net.ltgt.oidc.servlet.AbstractAuthorizationFilter.IS_PRIVATE_REQUEST_ATTRIBUTE_NAME;

  @Context protected HttpServletRequest servletRequest;

  @Override
  public void filter(ContainerRequestContext containerRequestContext) throws IOException {
    if (isAuthorized(containerRequestContext.getSecurityContext())) {
      containerRequestContext.setProperty(IS_PRIVATE_PROPERTY_NAME, true);
      return;
    }
    if (Utils.isNavigation(containerRequestContext)
        && Utils.isSafeMethod(containerRequestContext)) {
      redirectToAuthenticationEndpoint(containerRequestContext);
      return;
    }
    sendUnauthorized(containerRequestContext);
  }

  /** Returns whether the user is authorized. */
  protected abstract boolean isAuthorized(SecurityContext securityContext);

  /**
   * This method is called whenever the user is not authorized and the request is a {@linkplain
   * Utils#isSafeMethod safe} {@linkplain Utils#isNavigation navigation} request.
   *
   * <p>This implementation calls {@link #sendForbidden} whenever the user is authenticated, and
   * defers to the {@link #doRedirectToAuthenticationEndpoint} otherwise.
   */
  @ForOverride
  protected void redirectToAuthenticationEndpoint(ContainerRequestContext containerRequestContext) {
    if (containerRequestContext.getSecurityContext().getUserPrincipal() == null) {
      doRedirectToAuthenticationEndpoint(containerRequestContext);
    } else {
      sendForbidden(containerRequestContext);
    }
  }

  /**
   * This method is called whenever the user is not authorized and the request is a {@linkplain
   * Utils#isSafeMethod safe} {@linkplain Utils#isNavigation navigation} request.
   *
   * <p>The default implementation simply calls the globally configured {@link
   * AuthenticationRedirector}, and allows {@linkplain #configureAuthenticationRequest configuring
   * the authentication request}.
   *
   * @see #configureAuthenticationRequest
   * @see #sendUnauthorized
   */
  @ForOverride
  protected void doRedirectToAuthenticationEndpoint(
      ContainerRequestContext containerRequestContext) {
    var authenticationRedirector = getAuthenticationRedirector();
    authenticationRedirector.redirectToAuthenticationEndpoint(
        containerRequestContext,
        servletRequest,
        containerRequestContext.getUriInfo().getRequestUri().toASCIIString(),
        builder -> configureAuthenticationRequest(containerRequestContext, builder));
  }

  /**
   * Returns the configured authentication redirector.
   *
   * <p>The default implementation gets it from the {@linkplain #servletRequest request}'s
   * {@linkplain HttpServletRequest#getServletContext() servlet context}.
   */
  @ForOverride
  protected AuthenticationRedirector getAuthenticationRedirector() {
    return (AuthenticationRedirector)
        servletRequest
            .getServletContext()
            .getAttribute(AuthenticationRedirector.CONTEXT_ATTRIBUTE_NAME);
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
      ContainerRequestContext containerRequestContext, AuthenticationRequest.Builder builder) {}

  /**
   * This method is called whenever the user is not authorized and the request is <b>not</b> a
   * {@linkplain Utils#isSafeMethod safe} {@linkplain Utils#isNavigation navigation} request.
   *
   * <p>This implementation calls {@link #sendForbidden} whenever the user is authenticated, and
   * defers to {@link #doSendUnauthorized} otherwise.
   */
  @ForOverride
  protected void sendUnauthorized(ContainerRequestContext containerRequestContext) {
    if (containerRequestContext.getSecurityContext().getUserPrincipal() == null) {
      doSendUnauthorized(containerRequestContext);
    } else {
      sendForbidden(containerRequestContext);
    }
  }

  /**
   * This method is called whenever the user is not authorized and the request is <b>not</b> a
   * {@linkplain Utils#isSafeMethod safe} {@linkplain Utils#isNavigation navigation} request.
   *
   * <p>The default implementation simply throws a {@link NotAuthorizedException} without a {@code
   * WWW-Authenticate} response header. This is not strictly HTTP-compliant as it's missing the
   * {@code WWW-Authenticate} response header, but is a good way to signal the error to JavaScript
   * clients making an AJAX request.
   *
   * @see #sendUnauthorized
   * @see #redirectToAuthenticationEndpoint
   */
  @ForOverride
  protected void doSendUnauthorized(ContainerRequestContext containerRequestContext) {
    // XXX: this is not http-compliant as it's missing WWW-Authenticate
    throw new NotAuthorizedException(Response.status(Response.Status.UNAUTHORIZED).build());
  }

  /**
   * This method is called whenever the user is authenticated but not authorized.
   *
   * <p>The default implementation simply throws a {@link ForbiddenException}.
   */
  @ForOverride
  protected void sendForbidden(
      @SuppressWarnings("unused") ContainerRequestContext containerRequestContext) {
    throw new ForbiddenException();
  }
}
