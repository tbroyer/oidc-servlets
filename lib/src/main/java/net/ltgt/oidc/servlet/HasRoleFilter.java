package net.ltgt.oidc.servlet;

import static java.util.Objects.requireNonNull;

import com.google.errorprone.annotations.ForOverride;
import com.google.errorprone.annotations.OverridingMethodsMustInvokeSuper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Ensures the user {@linkplain HttpServletRequest#isUserInRole has a given role}.
 *
 * <p>When the user is not authorized, the default implementation will return a {@link
 * HttpServletResponse#SC_FORBIDDEN 403 Forbidden} error when the user is authenticated but is
 * missing the required role, and defers to the {@linkplain AbstractAuthorizationFilter parent
 * behavior} otherwise.
 *
 * <p>This filter should be installed <i>after</i> the {@link UserFilter} as it relies on {@link
 * HttpServletRequest#isUserInRole}.
 */
public class HasRoleFilter extends AbstractAuthorizationFilter {
  /** Name of the init parameter used to configure the expected user role. */
  public static final String ROLE = "role";

  private String role;

  public HasRoleFilter() {}

  /**
   * Constructs a filter that checks for the given role.
   *
   * <p>When this constructor is used, the {@link #ROLE} init parameter won't be read.
   */
  public HasRoleFilter(String role) {
    this.role = role;
  }

  @OverridingMethodsMustInvokeSuper
  @Override
  public void init() throws ServletException {
    super.init();
    if (role == null) {
      role = requireNonNull(getInitParameter(ROLE));
    }
  }

  @Override
  protected final boolean isAuthorized(HttpServletRequest req) {
    return req.isUserInRole(role);
  }

  /**
   * This method is called whenever the user is not authorized and the request is a {@linkplain
   * Utils#isSafeMethod safe} {@linkplain Utils#isNavigation navigation} request.
   *
   * <p>This implementation calls {@link #sendForbidden} whenever the user is authenticated, and
   * defers to the {@linkplain AbstractAuthorizationFilter#redirectToAuthenticationEndpoint parent
   * behavior} otherwise.
   */
  @ForOverride
  @Override
  protected void redirectToAuthenticationEndpoint(HttpServletRequest req, HttpServletResponse res)
      throws IOException, ServletException {
    if (req.getUserPrincipal() == null) {
      doRedirectToAuthenticationEndpoint(req, res);
    } else {
      sendForbidden(req, res);
    }
  }

  /**
   * Calls {@link #redirectToAuthenticationEndpoint} from the superclass. This is a hook allowing to
   * bypass this class' override's implementation.
   */
  @SuppressWarnings("ForOverride")
  protected final void doRedirectToAuthenticationEndpoint(
      HttpServletRequest req, HttpServletResponse res) throws IOException, ServletException {
    super.redirectToAuthenticationEndpoint(req, res);
  }

  /**
   * This method is called whenever is not authorized and the request is <b>not</b> a {@linkplain
   * Utils#isSafeMethod safe} {@linkplain Utils#isNavigation navigation} request.
   *
   * <p>This implementation calls {@link #sendForbidden} whenever the user is authenticated, and
   * defers to the {@linkplain AbstractAuthorizationFilter#sendUnauthorized parent behavior}
   * otherwise.
   */
  @ForOverride
  @Override
  protected void sendUnauthorized(HttpServletRequest req, HttpServletResponse res)
      throws IOException, ServletException {
    if (req.getUserPrincipal() == null) {
      doSendUnauthorized(req, res);
    } else {
      sendForbidden(req, res);
    }
  }

  /**
   * Calls {@link #sendUnauthorized} from the superclass. This is a hook allowing to bypass this
   * class' override's implementation.
   */
  @SuppressWarnings("ForOverride")
  protected final void doSendUnauthorized(HttpServletRequest req, HttpServletResponse res)
      throws IOException, ServletException {
    super.sendUnauthorized(req, res);
  }

  /**
   * This method is called whenever the user is authenticated but not authorized.
   *
   * <p>The default implementation simply calls {@code res.sendError(SC_FORBIDDEN)}.
   */
  @ForOverride
  protected void sendForbidden(HttpServletRequest req, HttpServletResponse res)
      throws IOException, ServletException {
    res.sendError(HttpServletResponse.SC_FORBIDDEN);
  }
}
