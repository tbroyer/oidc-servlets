package net.ltgt.oidc.servlet;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import org.checkerframework.checker.nullness.qual.Nullable;

/**
 * Checks whether the user is authenticated.
 *
 * <p>Initializes the request's {@link HttpServletRequest#getUserPrincipal() getUserPrincipal()} and
 * {@link HttpServletRequest#getRemoteUser() getRemoteUser()}, and implements its {@link
 * HttpServletRequest#isUserInRole isUserInRole(String)} for other filters and servlets down the
 * chain. The user principal will be created by the {@linkplain Configuration#createUserPrincipal
 * configuration} present in the {@link jakarta.servlet.ServletContext ServletContext}.
 *
 * <p>Invalidates the {@link jakarta.servlet.http.HttpSession HttpSession} if a {@link
 * LoggedOutSessionStore} is present in the {@code ServletContext} and the session has been recorded
 * as logged out on the OpenID Provider through the OpenID Connect Back-Channel Logout protocol.
 *
 * @see BackchannelLogoutServlet
 */
public class UserFilter extends HttpFilter {
  private Configuration configuration;
  private @Nullable LoggedOutSessionStore loggedOutSessionStore;

  @Override
  public void init() throws ServletException {
    configuration =
        (Configuration) getServletContext().getAttribute(Configuration.CONTEXT_ATTRIBUTE_NAME);
    loggedOutSessionStore =
        (LoggedOutSessionStore)
            getServletContext().getAttribute(LoggedOutSessionStore.CONTEXT_ATTRIBUTE_NAME);
  }

  @Override
  protected void doFilter(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
      throws IOException, ServletException {
    var session = req.getSession(false);
    if (session != null) {
      var sessionInfo = (SessionInfo) session.getAttribute(SessionInfo.SESSION_ATTRIBUTE_NAME);
      if (sessionInfo != null) {
        if (loggedOutSessionStore != null
            && sessionInfo.getIDTokenClaims().getSessionID() != null
            && loggedOutSessionStore.isLoggedOut(sessionInfo.getIDTokenClaims().getSessionID())) {
          session.invalidate();
        } else {
          req = wrapRequest(req, sessionInfo);
        }
      }
    }
    super.doFilter(req, res, chain);
  }

  private HttpServletRequest wrapRequest(HttpServletRequest req, SessionInfo sessionInfo) {
    return new HttpServletRequestWrapper(req) {
      private final UserPrincipal userPrincipal = configuration.createUserPrincipal(sessionInfo);

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
