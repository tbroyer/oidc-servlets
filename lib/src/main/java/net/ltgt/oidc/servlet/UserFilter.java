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

public class UserFilter extends HttpFilter {
  private @Nullable LoggedOutSessionStore loggedOutSessionStore;

  @Override
  public void init() throws ServletException {
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
            && sessionInfo.idTokenClaims().getSessionID() != null
            && loggedOutSessionStore.isLoggedOut(sessionInfo.idTokenClaims().getSessionID())) {
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
      private final UserPrincipal userPrincipal = new UserPrincipal(sessionInfo);

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
