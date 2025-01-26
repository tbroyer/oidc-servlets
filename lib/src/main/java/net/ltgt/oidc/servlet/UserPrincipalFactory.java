package net.ltgt.oidc.servlet;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Creates instances of {@link UserPrincipal} to be exposed as {@linkplain
 * HttpServletRequest#getUserPrincipal() requests' principal}.
 */
@FunctionalInterface
public interface UserPrincipalFactory {
  /**
   * Called on each request by the {@link UserFilter} to create the {@link UserPrincipal} for the
   * authenticated user; that will be exposed downward the filter chain as the {@linkplain
   * HttpServletRequest#getUserPrincipal() request's principal}.
   */
  UserPrincipal createUserPrincipal(SessionInfo sessionInfo);
}
