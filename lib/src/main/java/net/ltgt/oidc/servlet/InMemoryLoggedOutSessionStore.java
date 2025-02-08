package net.ltgt.oidc.servlet;

import com.nimbusds.openid.connect.sdk.claims.SessionID;
import java.util.Set;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/** An implementation of {@link LoggedOutSessionStore} that stores session IDs in memory. */
public class InMemoryLoggedOutSessionStore implements LoggedOutSessionStore {

  private final ConcurrentMap<SessionID, Set<String>> loggedInSessions =
      new ConcurrentSkipListMap<>();

  @Override
  public void logout(SessionID sessionID) {
    loggedInSessions.remove(sessionID);
  }

  @Override
  public boolean isLoggedOut(SessionID sessionID) {
    return loggedInSessions.getOrDefault(sessionID, Set.of()).isEmpty();
  }

  @Override
  public void acquire(SessionID sessionID, String sessionId) {
    loggedInSessions.compute(
        sessionID,
        (ignored, old) ->
            old == null
                ? Set.of(sessionId)
                : Stream.concat(old.stream(), Stream.of(sessionId))
                    .collect(Collectors.toUnmodifiableSet()));
  }

  @Override
  public void release(SessionID sessionID, String sessionId) {
    loggedInSessions.compute(
        sessionID,
        (ignored, old) -> {
          if (old == null) {
            return null;
          }
          if (!old.contains(sessionId)) {
            return old;
          }
          if (old.size() == 1) {
            return null;
          }
          return old.stream().filter(sessionId::equals).collect(Collectors.toUnmodifiableSet());
        });
  }

  @Override
  public void renew(SessionID sessionID, String oldSessionId, String newSessionId) {
    loggedInSessions.compute(
        sessionID,
        (ignored, old) -> {
          if (old == null) {
            // Strange, shouldn't have happened… treat as an acquire
            return Set.of(newSessionId);
          }
          return Stream.concat(old.stream().filter(oldSessionId::equals), Stream.of(newSessionId))
              .collect(Collectors.toUnmodifiableSet());
        });
  }
}
