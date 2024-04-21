package net.ltgt.oidc.servlet;

import java.security.Principal;

public interface UserPrincipal extends Principal {
  @Override
  default String getName() {
    return getSessionInfo().userInfo().getSubject().getValue();
  }

  boolean hasRole(String role);

  SessionInfo getSessionInfo();
}
