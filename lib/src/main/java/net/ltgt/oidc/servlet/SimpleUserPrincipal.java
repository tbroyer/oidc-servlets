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
