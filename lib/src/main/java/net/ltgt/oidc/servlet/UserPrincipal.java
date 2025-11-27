package net.ltgt.oidc.servlet;

import java.security.Principal;

/** An authenticated user. */
public interface UserPrincipal extends Principal {
  /**
   * Returns the user's name.
   *
   * @implSpec The default implementation returns the <i>subject</i> from the user information in
   *     {@link #getSessionInfo()}.
   */
  @Override
  default String getName() {
    return getSessionInfo().getUserInfo().getSubject().getValue();
  }

  /**
   * Returns whether the user has a given role.
   *
   * @see jakarta.servlet.http.HttpServletRequest#isUserInRole
   */
  boolean hasRole(String role);

  SessionInfo getSessionInfo();
}
