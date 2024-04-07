package net.ltgt.oidc.servlet.example.jetty;

import java.security.Principal;
import java.util.Collection;
import java.util.Optional;

public record UserPrincipal(SessionInfo sessionInfo) implements Principal {

  @Override
  public String getName() {
    return sessionInfo.userInfo().getSubject().getValue();
  }

  @SuppressWarnings("unchecked")
  public boolean hasRole(@SuppressWarnings("unused") String role) {
    // Look into Keycloak-specific role properties
    return Optional.ofNullable(sessionInfo.userInfo().getJSONObjectClaim("realm_access"))
        .map(realmAccess -> (Collection<String>) realmAccess.get("roles"))
        .map(roles -> roles.contains(role))
        .orElse(false);
  }
}
