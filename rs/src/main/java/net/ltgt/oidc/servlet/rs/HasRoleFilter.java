package net.ltgt.oidc.servlet.rs;

import static java.util.Objects.requireNonNull;

import com.google.errorprone.annotations.ForOverride;
import jakarta.annotation.Priority;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.SecurityContext;
import net.ltgt.oidc.servlet.UserPrincipal;

/**
 * Ensures the user {@linkplain SecurityContext#isUserInRole has a given role}.
 *
 * <p>When the user is not authorized, the default implementation will return a {@link
 * ForbiddenException 403 Forbidden} error when the user is authenticated but is missing the
 * required role, and defers to the {@linkplain AbstractAuthorizationFilter parent behavior}
 * otherwise.
 *
 * <p>An instance of this class needs to be registered through a {@link
 * jakarta.ws.rs.container.DynamicFeature DynamicFeature}, or a subclass needs to be created to be
 * able to create and use a {@linkplain jakarta.ws.rs.NameBinding name binding}.
 */
@Priority(Priorities.AUTHORIZATION)
public class HasRoleFilter extends AbstractAuthorizationFilter {
  private final String role;

  /** Constructs a filter that checks for the given role. */
  public HasRoleFilter(String role) {
    this.role = requireNonNull(role);
  }

  @Override
  protected final boolean isAuthorized(SecurityContext securityContext) {
    if (securityContext.getUserPrincipal() instanceof UserPrincipal userPrincipal) {
      return userPrincipal.hasRole(role);
    } else {
      return false;
    }
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
  protected void redirectToAuthenticationEndpoint(ContainerRequestContext containerRequestContext) {
    if (containerRequestContext.getSecurityContext().getUserPrincipal() == null) {
      doRedirectToAuthenticationEndpoint(containerRequestContext);
    } else {
      sendForbidden(containerRequestContext);
    }
  }

  /**
   * Calls {@link #redirectToAuthenticationEndpoint} from the superclass. This is a hook allowing to
   * bypass this class' override's implementation.
   */
  @SuppressWarnings("ForOverride")
  protected final void doRedirectToAuthenticationEndpoint(
      ContainerRequestContext containerRequestContext) {
    super.redirectToAuthenticationEndpoint(containerRequestContext);
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
  protected void sendUnauthorized(ContainerRequestContext containerRequestContext) {
    if (containerRequestContext.getSecurityContext().getUserPrincipal() == null) {
      doSendUnauthorized(containerRequestContext);
    } else {
      sendForbidden(containerRequestContext);
    }
  }

  /**
   * Calls {@link #sendUnauthorized} from the superclass. This is a hook allowing to bypass this
   * class' override's implementation.
   */
  @SuppressWarnings("ForOverride")
  protected final void doSendUnauthorized(ContainerRequestContext containerRequestContext) {
    super.sendUnauthorized(containerRequestContext);
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
