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
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import org.jspecify.annotations.Nullable;

/**
 * Checks whether the user is authenticated.
 *
 * <p>Initializes the request's {@link HttpServletRequest#getUserPrincipal() getUserPrincipal()} and
 * {@link HttpServletRequest#getRemoteUser() getRemoteUser()}, and implements its {@link
 * HttpServletRequest#isUserInRole isUserInRole(String)} for other filters and servlets down the
 * chain. The user principal will be created by a {@link UserPrincipalFactory} present in the {@link
 * jakarta.servlet.ServletContext ServletContext}.
 *
 * <p>Invalidates the {@link jakarta.servlet.http.HttpSession HttpSession} if a {@link
 * LoggedOutSessionStore} is present in the {@code ServletContext} and the session has been recorded
 * as logged out on the OpenID Provider through the OpenID Connect Back-Channel Logout protocol.
 *
 * @see BackchannelLogoutServlet
 */
public class UserFilter extends HttpFilter {
  private UserPrincipalFactory userPrincipalFactory;
  private LoggedOutSessionStore loggedOutSessionStore;

  public UserFilter() {}

  /**
   * Constructs a filter with the given {@link UserPrincipal} factory and no logged-out session
   * store.
   *
   * <p>When this constructor is used, the servlet context attributes won't be read.
   *
   * <p>This is equivalent to {@code new UserFilter(userPrincipalFactory, null)}.
   */
  public UserFilter(UserPrincipalFactory userPrincipalFactory) {
    this(userPrincipalFactory, null);
  }

  /**
   * Constructs a filter with the given {@link UserPrincipal} factory and (optional) logged-out
   * session store.
   *
   * <p>When this constructor is used, the servlet context attributes won't be read.
   */
  public UserFilter(
      UserPrincipalFactory userPrincipalFactory,
      @Nullable LoggedOutSessionStore loggedOutSessionStore) {
    this.userPrincipalFactory = requireNonNull(userPrincipalFactory);
    this.loggedOutSessionStore =
        loggedOutSessionStore != null ? loggedOutSessionStore : NullLoggedOutSessionStore.INSTANCE;
  }

  @OverridingMethodsMustInvokeSuper
  @Override
  public void init() throws ServletException {
    if (userPrincipalFactory == null) {
      userPrincipalFactory =
          (UserPrincipalFactory)
              getServletContext().getAttribute(UserPrincipalFactory.CONTEXT_ATTRIBUTE_NAME);
    }
    if (userPrincipalFactory == null) {
      userPrincipalFactory = SimpleUserPrincipal.FACTORY;
    }
    if (loggedOutSessionStore == null) {
      loggedOutSessionStore =
          (LoggedOutSessionStore)
              getServletContext().getAttribute(LoggedOutSessionStore.CONTEXT_ATTRIBUTE_NAME);
    }
    if (loggedOutSessionStore == null) {
      loggedOutSessionStore = NullLoggedOutSessionStore.INSTANCE;
    }
  }

  @Override
  protected void doFilter(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
      throws IOException, ServletException {
    var session = req.getSession(false);
    if (req.getUserPrincipal() == null && session != null) {
      var sessionInfo = (SessionInfo) session.getAttribute(SessionInfo.SESSION_ATTRIBUTE_NAME);
      if (sessionInfo != null) {
        if (sessionInfo.getIDTokenClaims().getSessionID() != null
            && loggedOutSessionStore.isLoggedOut(sessionInfo.getIDTokenClaims().getSessionID())) {
          session.invalidate();
        } else {
          var userPrincipal = userPrincipalFactory.createUserPrincipal(sessionInfo, session);
          req = wrapRequest(req, userPrincipal);
        }
      }
    }
    super.doFilter(req, res, chain);
  }

  private HttpServletRequest wrapRequest(HttpServletRequest req, UserPrincipal userPrincipal) {
    return new HttpServletRequestWrapper(req) {
      @Override
      public String getRemoteUser() {
        return userPrincipal.getName();
      }

      @Override
      public Principal getUserPrincipal() {
        return userPrincipal;
      }

      @Override
      public boolean isUserInRole(String role) {
        return userPrincipal.hasRole(role);
      }
    };
  }
}
