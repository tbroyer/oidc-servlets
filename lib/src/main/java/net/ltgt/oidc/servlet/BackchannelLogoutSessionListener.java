package net.ltgt.oidc.servlet;

import jakarta.servlet.http.HttpSessionEvent;
import jakarta.servlet.http.HttpSessionListener;

/**
 * Removes the OpenID Connect {@code sid} from the {@link LoggedOutSessionStore} whenever a session
 * is destroyed.
 *
 * <p>The {@code LoggedOutSessionStore} must have been added as a {@link
 * jakarta.servlet.ServletContext ServletContext} attribute under the name {@link
 * LoggedOutSessionStore#CONTEXT_ATTRIBUTE_NAME}.
 *
 * @see <a href="https://openid.net/specs/openid-connect-backchannel-1_0.html">OpenID Connect
 *     Back-Channel Logout 1.0</a>
 */
public class BackchannelLogoutSessionListener implements HttpSessionListener {
  @Override
  public void sessionDestroyed(HttpSessionEvent se) {
    var sessionInfo =
        (SessionInfo) se.getSession().getAttribute(SessionInfo.SESSION_ATTRIBUTE_NAME);
    var loggedOutSessionStore =
        (LoggedOutSessionStore)
            se.getSession()
                .getServletContext()
                .getAttribute(LoggedOutSessionStore.CONTEXT_ATTRIBUTE_NAME);
    if (sessionInfo != null
        && loggedOutSessionStore != null
        && sessionInfo.getIDTokenClaims().getSessionID() != null) {
      loggedOutSessionStore.forget(sessionInfo.getIDTokenClaims().getSessionID());
    }
  }
}
