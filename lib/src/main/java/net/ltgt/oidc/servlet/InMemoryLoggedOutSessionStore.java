/*
 * Copyright © 2026 Thomas Broyer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.ltgt.oidc.servlet;

import static java.util.function.Predicate.not;

import com.google.errorprone.annotations.ForOverride;
import com.nimbusds.openid.connect.sdk.claims.SessionID;
import java.util.Set;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * An implementation of {@link LoggedOutSessionStore} that stores session IDs in memory.
 *
 * <p>A subclass can override {@link #doLogout} to effectively invalidate sessions.
 */
public class InMemoryLoggedOutSessionStore implements LoggedOutSessionStore {

  private final ConcurrentMap<SessionID, Set<String>> loggedInSessions =
      new ConcurrentSkipListMap<>();

  @Override
  public void logout(SessionID sessionID) {
    var loggedOutSessions = loggedInSessions.remove(sessionID);
    if (loggedOutSessions != null) {
      doLogout(loggedOutSessions);
    }
  }

  /**
   * Can be implemented to effectively invalidate sessions.
   *
   * <p>A Jetty implementation could thus use {@code getManagedSession(sessionId).invalidate()} on
   * the context's {@code SessionManager}, a Tomcat implementation {@code
   * findSession(sessionId).invalidate()} on the context's {@code Manager}, an Undertow
   * implementation {@code getSession(sessionId).invalidate(null)} on the context's {@code
   * SessionManager}, etc.
   */
  @ForOverride
  protected void doLogout(Set<String> sessionIds) {}

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
          return old.stream()
              .filter(not(sessionId::equals))
              .collect(Collectors.toUnmodifiableSet());
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
          return Stream.concat(
                  old.stream().filter(not(oldSessionId::equals)), Stream.of(newSessionId))
              .collect(Collectors.toUnmodifiableSet());
        });
  }
}
