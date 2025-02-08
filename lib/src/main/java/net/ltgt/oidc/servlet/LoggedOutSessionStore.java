package net.ltgt.oidc.servlet;

import com.nimbusds.openid.connect.sdk.claims.SessionID;

/**
 * Tracks {@link SessionID} values of sessions logged out with the OpenID Connect Back-Channel
 * Logout protocol through the {@link BackchannelLogoutServlet}.
 *
 * <p>Those sessions will be invalidated by the {@link UserFilter} when a corresponding {@link
 * jakarta.servlet.http.HttpSession HttpSession} is being used. The {@link
 * BackchannelLogoutSessionListener} is responsible for notifying this store of the {@code
 * SessionID} that are being used by sessions.
 *
 * <p>Implementations could also directly invalidate the session if possible, rather than only
 * somehow marking it as logged out to later be invalidated by the {@code UserFilter}. In this case,
 * the {@code BackchannelLogoutSessionListener} might not be necessary depending on the
 * implementation.
 *
 * @see InMemoryLoggedOutSessionStore
 * @see UserFilter
 * @see BackchannelLogoutServlet
 * @see BackchannelLogoutSessionListener
 * @see <a href="https://openid.net/specs/openid-connect-backchannel-1_0.html">OpenID Connect
 *     Back-Channel Logout 1.0</a>
 */
public interface LoggedOutSessionStore {
  String CONTEXT_ATTRIBUTE_NAME = LoggedOutSessionStore.class.getName();

  /**
   * Records the given session ID as having been logged out at the OpenID Provider.
   *
   * <p>Implementations could also directly invalidate the session if possible, rather than only
   * marking it as logged out to later be invalidated by the {@code UserFilter}. In this case, the
   * {@code BackchannelLogoutSessionListener} might not be necessary depending on the
   * implementation.
   *
   * @see BackchannelLogoutServlet
   */
  void logout(SessionID sessionID);

  /**
   * Returns whether the given session ID has been {@linkplain #logout logged out}.
   *
   * <p>Called by {@link UserFilter} to possibly invalidate sessions as they're being tentatively
   * used.
   *
   * @see #logout
   * @see UserFilter
   */
  default boolean isLoggedOut(SessionID sessionID) {
    return false;
  }

  /**
   * Associates the OpenID Provider session ID with a new application's HTTP session.
   *
   * @see BackchannelLogoutSessionListener
   */
  default void acquire(SessionID sessionID, String sessionId) {}

  /**
   * Dissociates the OpenID Provider session ID from an application's HTTP session.
   *
   * @see BackchannelLogoutSessionListener
   */
  default void release(SessionID sessionID, String sessionId) {}

  /**
   * Notifies the store that the application's HTTP session, associated with a given OpenID Provider
   * session ID, has changed ID.
   */
  default void renew(SessionID sessionID, String oldSessionId, String newSessionId) {}
}
