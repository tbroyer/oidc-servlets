package net.ltgt.oidc.servlet;

import static java.util.Objects.requireNonNull;

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
  private LoggedOutSessionStore loggedOutSessionStore;

  public UserFilter() {}

  /**
   * Constructs a filter with the given configuration and no logged-out session store.
   *
   * <p>When this constructor is used, the servlet context attributes won't be read.
   *
   * <p>This is equivalent to {@code new UserFilter(configuration, null)}.
   */
  public UserFilter(Configuration configuration) {
    this(configuration, null);
  }

  /**
   * Constructs a filter with the given configuration and (optional) logged-out session store.
   *
   * <p>When this constructor is used, the servlet context attributes won't be read.
   */
  public UserFilter(
      Configuration configuration, @Nullable LoggedOutSessionStore loggedOutSessionStore) {
    this.configuration = requireNonNull(configuration);
    this.loggedOutSessionStore =
        loggedOutSessionStore != null ? loggedOutSessionStore : NullLoggedOutSessionStore.INSTANCE;
  }

  @Override
  public void init() throws ServletException {
    if (configuration == null) {
      configuration =
          (Configuration) getServletContext().getAttribute(Configuration.CONTEXT_ATTRIBUTE_NAME);
    }
    requireNonNull(configuration);
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
    if (session != null) {
      var sessionInfo = (SessionInfo) session.getAttribute(SessionInfo.SESSION_ATTRIBUTE_NAME);
      if (sessionInfo != null) {
        if (sessionInfo.getIDTokenClaims().getSessionID() != null
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
