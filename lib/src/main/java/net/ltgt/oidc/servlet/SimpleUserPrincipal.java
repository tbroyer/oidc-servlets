package net.ltgt.oidc.servlet;

import static java.util.Objects.requireNonNull;

/** A simple {@link UserPrincipal} implementation with no role at all. */
public class SimpleUserPrincipal implements UserPrincipal {
  public static final UserPrincipalFactory FACTORY =
      (sessionInfo, unused) -> new SimpleUserPrincipal(sessionInfo);

  private final SessionInfo sessionInfo;

  public SimpleUserPrincipal(SessionInfo sessionInfo) {
    this.sessionInfo = requireNonNull(sessionInfo);
  }

  @Override
  public boolean hasRole(String role) {
    return false;
  }

  @Override
  public SessionInfo getSessionInfo() {
    return sessionInfo;
  }
}
