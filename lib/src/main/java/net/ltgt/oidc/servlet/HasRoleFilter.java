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

import com.google.errorprone.annotations.OverridingMethodsMustInvokeSuper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Ensures the user {@linkplain UserPrincipal#hasRole has a given role}.
 *
 * <p>This filter should be installed <i>after</i> the {@link UserFilter} as it relies on {@link
 * HttpServletRequest#getUserPrincipal()}.
 */
public class HasRoleFilter extends AbstractAuthorizationFilter {
  /** Name of the init parameter used to configure the expected user role. */
  public static final String ROLE = "role";

  private String role;

  public HasRoleFilter() {}

  /**
   * Constructs a filter that checks for the given role.
   *
   * <p>When this constructor is used, the {@link #ROLE} init parameter won't be read; the
   * {@linkplain AuthenticationRedirector#CONTEXT_ATTRIBUTE_NAME servlet context attribute} will be
   * read though.
   */
  public HasRoleFilter(String role) {
    this.role = requireNonNull(role);
  }

  /**
   * Constructs a filter with the given authentication redirector.
   *
   * <p>When this constructor is used, the {@linkplain
   * AuthenticationRedirector#CONTEXT_ATTRIBUTE_NAME servlet context attribute} won't be read,
   * though the role will be read from the {@link #ROLE} init parameter.
   */
  public HasRoleFilter(AuthenticationRedirector authenticationRedirector) {
    super(authenticationRedirector);
  }

  /**
   * Constructs a filter with the given authentication redirector and role.
   *
   * <p>When this constructor is used, the {@linkplain
   * AuthenticationRedirector#CONTEXT_ATTRIBUTE_NAME servlet context attribute} and the {@link
   * #ROLE} init parameter won't be read.
   */
  public HasRoleFilter(AuthenticationRedirector authenticationRedirector, String role) {
    super(authenticationRedirector);
    this.role = requireNonNull(role);
  }

  @OverridingMethodsMustInvokeSuper
  @Override
  public void init() throws ServletException {
    super.init();
    if (role == null) {
      role = requireNonNull(getInitParameter(ROLE));
    }
  }

  @Override
  protected final boolean isAuthorized(HttpServletRequest req) {
    if (req.getUserPrincipal() instanceof UserPrincipal userPrincipal) {
      return userPrincipal.hasRole(role);
    } else {
      return false;
    }
  }
}
