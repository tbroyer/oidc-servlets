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

/** Ensures the user {@linkplain HttpServletRequest#getUserPrincipal is authenticated}. */
public class IsAuthenticatedFilter extends AbstractAuthorizationFilter {

  public IsAuthenticatedFilter() {}

  /**
   * Constructs a filter with the given authentication redirector.
   *
   * <p>When this constructor is used, the {@linkplain
   * AuthenticationRedirector#CONTEXT_ATTRIBUTE_NAME servlet context attribute} won't be read.
   */
  public IsAuthenticatedFilter(AuthenticationRedirector authenticationRedirector) {
    super(authenticationRedirector);
  }

  @Override
  protected boolean isAuthorized(HttpServletRequest req) {
    return req.getUserPrincipal() instanceof UserPrincipal;
  }
}
