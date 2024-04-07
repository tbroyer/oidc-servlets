package net.ltgt.oidc.servlet.example.jetty;

import java.security.Principal;

public record UserPrincipal(SessionInfo sessionInfo) implements Principal {

  @Override
  public String getName() {
    return sessionInfo.userInfo().getSubject().getValue();
  }
}
