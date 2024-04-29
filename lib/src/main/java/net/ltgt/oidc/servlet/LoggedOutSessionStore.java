package net.ltgt.oidc.servlet;

import com.nimbusds.openid.connect.sdk.claims.SessionID;

/**
 * Tracks {@link SessionID} values of sessions logged out with the OpenID Connect Back-Channel
 * Logout protocol through the {@link BackchannelLogoutServlet}.
 *
 * <p>Those sessions will be invalidated by the {@link UserFilter} when a corresponding {@link
 * jakarta.servlet.http.HttpSession HttpSession} is being used, and once destroyed the {@link
 * BackchannelLogoutSessionListener} is responsible for notifying this store so the {@code
 * SessionID} can be forgotten (to prevent the store growing indefinitely).
 *
 * <p>Implementations could also directly invalidate the session if possible, rather than only
 * marking it as logged out to later be invalidated by the {@code UserFilter}. In this case, the
 * {@code BackchannelLogoutSessionListener} might not be necessary.
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
   * {@code BackchannelLogoutSessionListener} might not be necessary.
   *
   * @see BackchannelLogoutServlet
   */
  void logout(SessionID sessionID);

  /**
   * Returns whether the given session ID has been logged out.
   *
   * @see #logout
   * @see UserFilter
   */
  boolean isLoggedOut(SessionID sessionID);

  /**
   * Forgets about the given session ID.
   *
   * <p>This method should be called when the corresponding {@link jakarta.servlet.http.HttpSession
   * HttpSession} has been destroyed, to release memory.
   *
   * @see BackchannelLogoutSessionListener
   */
  void forget(SessionID sessionID);
}
