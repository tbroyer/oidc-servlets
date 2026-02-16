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

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

/**
 * Creates instances of {@link UserPrincipal} to be exposed as {@linkplain
 * HttpServletRequest#getUserPrincipal() requests' principal}.
 */
@FunctionalInterface
public interface UserPrincipalFactory {
  String CONTEXT_ATTRIBUTE_NAME = UserPrincipalFactory.class.getName();

  /**
   * Called on each request by the {@link UserFilter} to create the {@link UserPrincipal} for the
   * authenticated user; that will be exposed downward the filter chain as the {@linkplain
   * HttpServletRequest#getUserPrincipal() request's principal}.
   *
   * <p>This method can use data put in the session by {@link #userAuthenticated} to expose in a
   * custom {@link UserPrincipal} implementation.
   */
  UserPrincipal createUserPrincipal(SessionInfo sessionInfo, HttpSession session);

  /**
   * Called by the {@link CallbackServlet} when the user is successfully authenticated.
   *
   * <p>This can be used to load additional user data into the session, that can be used by {@link
   * #createUserPrincipal} when creating the principal, and/or to synchronize user information from
   * the {@link SessionInfo} into a local database.
   */
  default void userAuthenticated(SessionInfo sessionInfo, HttpSession session) {}
}
