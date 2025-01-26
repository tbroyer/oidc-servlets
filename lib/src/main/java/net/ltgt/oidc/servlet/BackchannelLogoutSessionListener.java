package net.ltgt.oidc.servlet;

import static java.util.Objects.requireNonNull;

import jakarta.servlet.http.HttpSessionEvent;
import jakarta.servlet.http.HttpSessionListener;
import org.jspecify.annotations.Nullable;

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
  private @Nullable LoggedOutSessionStore loggedOutSessionStore;

  public BackchannelLogoutSessionListener() {}

  /**
   * Constructs a listener with the given logged-out session store.
   *
   * <p>When this constructor is used, the {@linkplain LoggedOutSessionStore#CONTEXT_ATTRIBUTE_NAME
   * servlet context attribute} won't be read.
   */
  public BackchannelLogoutSessionListener(LoggedOutSessionStore loggedOutSessionStore) {
    this.loggedOutSessionStore = requireNonNull(loggedOutSessionStore);
  }

  @Override
  public void sessionDestroyed(HttpSessionEvent se) {
    var sessionInfo =
        (SessionInfo) se.getSession().getAttribute(SessionInfo.SESSION_ATTRIBUTE_NAME);
    var loggedOutSessionStore = this.loggedOutSessionStore;
    if (loggedOutSessionStore == null) {
      loggedOutSessionStore =
          (LoggedOutSessionStore)
              se.getSession()
                  .getServletContext()
                  .getAttribute(LoggedOutSessionStore.CONTEXT_ATTRIBUTE_NAME);
    }
    if (sessionInfo != null
        && loggedOutSessionStore != null
        && sessionInfo.getIDTokenClaims().getSessionID() != null) {
      loggedOutSessionStore.forget(sessionInfo.getIDTokenClaims().getSessionID());
    }
  }
}
