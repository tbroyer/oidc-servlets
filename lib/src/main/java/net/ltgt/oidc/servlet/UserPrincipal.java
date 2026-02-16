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
