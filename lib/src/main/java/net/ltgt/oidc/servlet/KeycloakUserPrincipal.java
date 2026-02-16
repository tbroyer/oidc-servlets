/*
 * Copyright © 2026 Thomas Broyer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
