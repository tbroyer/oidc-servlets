package net.ltgt.oidc.servlet.example.jetty;

import jakarta.servlet.http.HttpSessionEvent;
import jakarta.servlet.http.HttpSessionListener;

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
        && sessionInfo.idTokenClaims().getSessionID() != null) {
      loggedOutSessionStore.forget(sessionInfo.idTokenClaims().getSessionID());
    }
  }
}
