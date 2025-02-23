package net.ltgt.oidc.servlet.rs;

import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.core.SecurityContext;
import jakarta.ws.rs.ext.Provider;
import net.ltgt.oidc.servlet.UserPrincipal;

/**
 * Ensures the user {@linkplain SecurityContext#getUserPrincipal is authenticated}.
 *
 * <p>The Jakarta RS resource class or method must be annotated with {@link IsAuthenticated} to
 * apply this filter.
 *
 * @see IsAuthenticated
 */
@Provider
@IsAuthenticated
@Priority(Priorities.AUTHORIZATION)
public class IsAuthenticatedFilter extends AbstractAuthorizationFilter {
  @Override
  protected boolean isAuthorized(SecurityContext securityContext) {
    return securityContext.getUserPrincipal() instanceof UserPrincipal;
  }
}
