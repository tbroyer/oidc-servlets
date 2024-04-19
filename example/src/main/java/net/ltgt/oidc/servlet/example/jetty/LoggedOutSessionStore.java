package net.ltgt.oidc.servlet.example.jetty;

import com.nimbusds.openid.connect.sdk.claims.SessionID;
import java.util.Set;
import java.util.concurrent.ConcurrentSkipListSet;

public class LoggedOutSessionStore {
  public static final String CONTEXT_ATTRIBUTE_NAME = LoggedOutSessionStore.class.getName();

  private final Set<SessionID> loggedOutSessions = new ConcurrentSkipListSet<>();

  public void logout(SessionID sessionID) {
    loggedOutSessions.add(sessionID);
  }

  public boolean isLoggedOut(SessionID sessionID) {
    return loggedOutSessions.contains(sessionID);
  }

  public void forget(SessionID sessionID) {
    loggedOutSessions.remove(sessionID);
  }
}
