package net.ltgt.oidc.servlet;

/** A simple {@link UserPrincipal} implementation with no role at all. */
public class SimpleUserPrincipal implements UserPrincipal {
  private final SessionInfo sessionInfo;

  public SimpleUserPrincipal(SessionInfo sessionInfo) {
    this.sessionInfo = sessionInfo;
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
