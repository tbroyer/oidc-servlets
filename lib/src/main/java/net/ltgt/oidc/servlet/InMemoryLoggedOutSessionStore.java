package net.ltgt.oidc.servlet;

import com.nimbusds.openid.connect.sdk.claims.SessionID;
import java.util.Set;
import java.util.concurrent.ConcurrentSkipListSet;

/** An implementation of {@link LoggedOutSessionStore} that stores session IDs in memory. */
public class InMemoryLoggedOutSessionStore implements LoggedOutSessionStore {

  private final Set<SessionID> loggedOutSessions = new ConcurrentSkipListSet<>();

  @Override
  public void logout(SessionID sessionID) {
    loggedOutSessions.add(sessionID);
  }

  @Override
  public boolean isLoggedOut(SessionID sessionID) {
    return loggedOutSessions.contains(sessionID);
  }

  @Override
  public void forget(SessionID sessionID) {
    loggedOutSessions.remove(sessionID);
  }
}
