package net.ltgt.oidc.servlet;

import static java.util.Objects.requireNonNull;

import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpSessionAttributeListener;
import jakarta.servlet.http.HttpSessionBindingEvent;
import jakarta.servlet.http.HttpSessionEvent;
import jakarta.servlet.http.HttpSessionIdListener;
import java.util.Objects;
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
public class BackchannelLogoutSessionListener
    implements HttpSessionAttributeListener, HttpSessionIdListener {
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
  public void attributeAdded(HttpSessionBindingEvent event) {
    if (event.getName().equals(SessionInfo.SESSION_ATTRIBUTE_NAME)) {
      var sid = ((SessionInfo) event.getValue()).getIDTokenClaims().getSessionID();
      var loggedOutSessionStore = getLoggedOutSessionStore(event.getSession());
      if (sid != null && loggedOutSessionStore != null) {
        loggedOutSessionStore.acquire(sid, event.getSession().getId());
      }
    }
  }

  @Override
  public void attributeRemoved(HttpSessionBindingEvent event) {
    if (event.getName().equals(SessionInfo.SESSION_ATTRIBUTE_NAME)) {
      var sid = ((SessionInfo) event.getValue()).getIDTokenClaims().getSessionID();
      var loggedOutSessionStore = getLoggedOutSessionStore(event.getSession());
      if (sid != null && loggedOutSessionStore != null) {
        loggedOutSessionStore.release(sid, event.getSession().getId());
      }
    }
  }

  @Override
  public void attributeReplaced(HttpSessionBindingEvent event) {
    if (event.getName().equals(SessionInfo.SESSION_ATTRIBUTE_NAME)) {
      var oldSid = ((SessionInfo) event.getValue()).getIDTokenClaims().getSessionID();
      var newSid =
          ((SessionInfo) event.getSession().getAttribute(SessionInfo.SESSION_ATTRIBUTE_NAME))
              .getIDTokenClaims()
              .getSessionID();
      if (!Objects.equals(oldSid, newSid)) {
        var loggedOutSessionStore = getLoggedOutSessionStore(event.getSession());
        if (loggedOutSessionStore != null) {
          if (oldSid != null) {
            loggedOutSessionStore.release(oldSid, event.getSession().getId());
          }
          if (newSid != null) {
            loggedOutSessionStore.acquire(newSid, event.getSession().getId());
          }
        }
      }
    }
  }

  @Override
  public void sessionIdChanged(HttpSessionEvent event, String oldSessionId) {
    var sessionInfo =
        (SessionInfo) event.getSession().getAttribute(SessionInfo.SESSION_ATTRIBUTE_NAME);
    if (sessionInfo == null) {
      return;
    }
    var sid = sessionInfo.getIDTokenClaims().getSessionID();
    var loggedOutSessionStore = getLoggedOutSessionStore(event.getSession());
    if (sid != null && loggedOutSessionStore != null) {
      loggedOutSessionStore.renew(sid, oldSessionId, event.getSession().getId());
    }
  }

  private @Nullable LoggedOutSessionStore getLoggedOutSessionStore(HttpSession session) {
    if (this.loggedOutSessionStore != null) {
      return this.loggedOutSessionStore;
    }
    return (LoggedOutSessionStore)
        session.getServletContext().getAttribute(LoggedOutSessionStore.CONTEXT_ATTRIBUTE_NAME);
  }
}
