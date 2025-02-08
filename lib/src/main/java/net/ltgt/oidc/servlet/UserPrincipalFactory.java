package net.ltgt.oidc.servlet;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

/**
 * Creates instances of {@link UserPrincipal} to be exposed as {@linkplain
 * HttpServletRequest#getUserPrincipal() requests' principal}.
 */
@FunctionalInterface
public interface UserPrincipalFactory {
  String CONTEXT_ATTRIBUTE_NAME = UserPrincipalFactory.class.getName();

  /**
   * Called on each request by the {@link UserFilter} to create the {@link UserPrincipal} for the
   * authenticated user; that will be exposed downward the filter chain as the {@linkplain
   * HttpServletRequest#getUserPrincipal() request's principal}.
   *
   * <p>This method can use data put in the session by {@link #userAuthenticated} to expose in a
   * custom {@link UserPrincipal} implementation.
   */
  UserPrincipal createUserPrincipal(SessionInfo sessionInfo, HttpSession session);

  /**
   * Called by the {@link CallbackServlet} when the user is successfully authenticated to load
   * additional user data into the session, that can be used by {@link #createUserPrincipal} when
   * creating the principal.
   */
  default void userAuthenticated(SessionInfo sessionInfo, HttpSession session) {}
}
