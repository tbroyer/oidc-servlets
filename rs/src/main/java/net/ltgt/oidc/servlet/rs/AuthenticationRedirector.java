package net.ltgt.oidc.servlet.rs;

import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Response;
import java.util.function.Consumer;
import net.ltgt.oidc.servlet.CallbackServlet;
import net.ltgt.oidc.servlet.Configuration;
import net.ltgt.oidc.servlet.LoginServlet;
import org.jspecify.annotations.Nullable;

/**
 * Responsible for redirecting to the OpenID Provider.
 *
 * <p>An instance of this class needs to be added as a {@link jakarta.servlet.ServletContext
 * ServletContext} attribute under the name {@link #CONTEXT_ATTRIBUTE_NAME}, to be used by the
 * {@linkplain net.ltgt.oidc.servlet.AbstractAuthorizationFilter servlet authorization filters},
 * {@linkplain net.ltgt.oidc.servlet.rs.AbstractAuthorizationFilter Jakarta-RS authorization
 * filters}, or the {@link LoginServlet}.
 *
 * <p>In other words, if you're using Jakarta RS, then use an instance of this class instead of than
 * {@link net.ltgt.oidc.servlet.AuthenticationRedirector}.
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect Core 1.0</a>
 * @see net.ltgt.oidc.servlet.AbstractAuthorizationFilter
 * @see net.ltgt.oidc.servlet.rs.AbstractAuthorizationFilter
 * @see net.ltgt.oidc.servlet.IsAuthenticatedFilter
 * @see net.ltgt.oidc.servlet.rs.IsAuthenticatedFilter
 * @see net.ltgt.oidc.servlet.HasRoleFilter
 * @see net.ltgt.oidc.servlet.rs.HasRoleFilter
 * @see LoginServlet
 */
public class AuthenticationRedirector extends net.ltgt.oidc.servlet.AuthenticationRedirector {

  public AuthenticationRedirector(Configuration configuration, String callbackPath) {
    super(configuration, callbackPath);
  }

  /**
   * Redirects to the OpenID Provider, returning to the given page when coming back.
   *
   * <p>This is equivalent to {@code redirectToAuthenticationEndpoint(req, res, returnTo, null)}.
   */
  public void redirectToAuthenticationEndpoint(
      ContainerRequestContext containerRequestContext, HttpServletRequest req, String returnTo) {
    redirectToAuthenticationEndpoint(containerRequestContext, req, returnTo, null);
  }

  /**
   * Redirects to the OpenID Provider, returning to the given page when coming back, and possibly
   * configuring the authentication request further.
   *
   * <p>The target page should be given as an absolute path (possibly with a query string), though a
   * full URL would be accepted as long as it's the same <a
   * href="https://datatracker.ietf.org/doc/html/rfc6454">origin</a>. It will be saved in the
   * session to be redirected to from the {@link CallbackServlet}.
   */
  public void redirectToAuthenticationEndpoint(
      ContainerRequestContext containerRequestContext,
      HttpServletRequest req,
      String returnTo,
      @Nullable Consumer<AuthenticationRequest.Builder> configureAuthenticationRequest) {
    redirectToAuthenticationEndpoint(
        req.getSession(),
        returnTo,
        configureAuthenticationRequest,
        containerRequestContext.getUriInfo().getRequestUri(),
        uri -> containerRequestContext.abortWith(Response.seeOther(uri).build()));
  }
}
