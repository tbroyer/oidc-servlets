package net.ltgt.oidc.servlet.rs;

import com.google.errorprone.annotations.ForOverride;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import jakarta.annotation.Priority;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.ClientErrorException;
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
  protected void redirectToAuthenticationEndpoint(ContainerRequestContext containerRequestContext) {
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
   * This method is called whenever is not authorized and the request is <b>not</b> a {@linkplain
   * Utils#isSafeMethod safe} {@linkplain Utils#isNavigation navigation} request.
   *
   * <p>The default implementation simply throws {@code new ClientErrorException(UNAUTHORIZED)}.
   * This is not strictly HTTP-compliant as it's missing the {@code WWW-Authenticate} response
   * header, but is a good way to signal the error to JavaScript clients making an AJAX request.
   *
   * @see #redirectToAuthenticationEndpoint
   * @see HasRoleFilter
   */
  @ForOverride
  protected void sendUnauthorized(ContainerRequestContext containerRequestContext) {
    // XXX: this is not http-compliant as it's missing WWW-Authenticate
    throw new ClientErrorException(Response.Status.UNAUTHORIZED);
  }
}
