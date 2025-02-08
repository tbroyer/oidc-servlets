package net.ltgt.oidc.servlet;

import static java.util.Objects.requireNonNull;

import java.util.Collection;
import java.util.Optional;

/** A {@link UserPrincipal} that extracts Keycloak <i>realm</i> roles from the user information. */
public class KeycloakUserPrincipal implements UserPrincipal {
  public static final UserPrincipalFactory FACTORY =
      (sessionInfo, unused) -> new KeycloakUserPrincipal(sessionInfo);

  private final SessionInfo sessionInfo;

  public KeycloakUserPrincipal(SessionInfo sessionInfo) {
    this.sessionInfo = requireNonNull(sessionInfo);
  }

  @Override
  @SuppressWarnings("unchecked")
  public boolean hasRole(String role) {
    // Look into Keycloak-specific role properties
    return Optional.ofNullable(sessionInfo.getUserInfo().getJSONObjectClaim("realm_access"))
        .map(realmAccess -> (Collection<String>) realmAccess.get("roles"))
        .map(roles -> roles.contains(role))
        .orElse(false);
  }

  @Override
  public SessionInfo getSessionInfo() {
    return sessionInfo;
  }
}
