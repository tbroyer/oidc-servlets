package net.ltgt.oidc.servlet;

import static java.util.Objects.requireNonNull;

import com.google.errorprone.annotations.OverridingMethodsMustInvokeSuper;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.LogoutRequest;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import org.jspecify.annotations.Nullable;

/**
 * This servlet starts the logout workflow and possibly redirects back to a given URL afterward.
 *
 * <p>The post-logout redirection is conditioned to configuration of a {@link
 * #POST_LOGOUT_REDIRECT_PATH} init parameter. This should be a public page, otherwise the user will
 * directly be sent back to the OpenID Provider for signing in again, and it should be properly
 * registered at the OpenID Provider in the {@code post_logout_redirect_uris} client metadata.
 *
 * <p>If this post-logout redirect path is a {@link LogoutCallbackServlet}, this should be indicated
 * with a {@link #USE_LOGOUT_STATE} init parameter with the value {@code true}. The final redirect
 * target will have to be sent as a {@link Utils#RETURN_TO_PARAMETER_NAME} form parameter. It should
 * be given as an absolute path (possibly with a query string), though a full URL would be accepted
 * as long as it's the same <a href="https://datatracker.ietf.org/doc/html/rfc6454">origin</a>.
 *
 * @see <a href="https://openid.net/specs/openid-connect-rpinitiated-1_0.html">OpenID Connect
 *     RP-Initiated Logout 1.0</a>
 */
public class LogoutServlet extends HttpServlet {
  public static final String POST_LOGOUT_REDIRECT_PATH = "post-logout-redirect-path";
  public static final String USE_LOGOUT_STATE = "use-logout-state";

  private Configuration configuration;
  private @Nullable String postLogoutRedirectPath;
  private Boolean useLogoutState;

  public LogoutServlet() {}

  /**
   * Constructs a logout servlet with the given post-logout redirect path.
   *
   * <p>When this constructor is used, <i>logout state</i> won't be used, and the init parameters
   * won't be read; the {@linkplain Configuration#CONTEXT_ATTRIBUTE_NAME configuration} servlet
   * context attribute will be read though.
   *
   * <p>This is equivalent to {@code new LogoutServlet(postLogoutRedirectPath, false)}.
   */
  public LogoutServlet(String postLogoutRedirectPath) {
    this(postLogoutRedirectPath, false);
  }

  /**
   * Constructs a logout servlet with the given post-logout redirect path and whether to use
   * <i>logout state</i>.
   *
   * <p>When this constructor is used, the init parameters won't be read; the {@linkplain
   * Configuration#CONTEXT_ATTRIBUTE_NAME configuration} servlet context attribute will be read
   * though.
   */
  public LogoutServlet(String postLogoutRedirectPath, boolean useLogoutState) {
    this.postLogoutRedirectPath = postLogoutRedirectPath;
    this.useLogoutState = useLogoutState;
  }

  /**
   * Constructs a logout servlet with the given configuration and post-logout redirect path.
   *
   * <p>When this constructor is used, <i>logout state</i> won't be used, and neither the servlet
   * context attribute nor the init parameters will be read.
   *
   * <p>This is equivalent to {@code new LogoutServlet(configuration, postLogoutRedirectPath,
   * false)}.
   */
  public LogoutServlet(Configuration configuration, String postLogoutRedirectPath) {
    this(configuration, postLogoutRedirectPath, false);
  }

  /**
   * Constructs a logout servlet with the given configuration and post-logout redirect path, and
   * whether to use <i>logout state</i>.
   *
   * <p>When this constructor is used, neither the servlet context attribute nor the init parameters
   * will be read.
   */
  public LogoutServlet(
      Configuration configuration, String postLogoutRedirectPath, boolean useLogoutState) {
    this.configuration = requireNonNull(configuration);
    this.postLogoutRedirectPath = requireNonNull(postLogoutRedirectPath);
    this.useLogoutState = useLogoutState;
  }

  @OverridingMethodsMustInvokeSuper
  @Override
  public void init() throws ServletException {
    if (configuration == null) {
      configuration =
          (Configuration) getServletContext().getAttribute(Configuration.CONTEXT_ATTRIBUTE_NAME);
    }
    if (postLogoutRedirectPath == null) {
      postLogoutRedirectPath = getInitParameter(POST_LOGOUT_REDIRECT_PATH);
    }
    if (useLogoutState == null) {
      useLogoutState = Boolean.parseBoolean(getInitParameter(USE_LOGOUT_STATE));
    }
    requireNonNull(configuration, "configuration");
    // No need to check useLogoutState as Boolean.parseBoolean returns a non-null value
  }

  // XXX: what to do on GET? show interstitial?

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException, IOException {
    if (!Utils.isNavigation(req)) {
      resp.sendError(HttpServletResponse.SC_BAD_REQUEST);
      return;
    }
    // XXX: prevent CSRF with synchronizer token pattern? off-load to a filter? (OWASP CSRFGuard?)
    // XXX: what to do with CSRF? redirect? show interstitial? (fallback to doGet) send error?
    if (!Utils.isSameOrigin(req)) {
      Utils.sendRedirect(resp, "/");
      return;
    }

    var session = req.getSession(false);
    if (session == null) {
      Utils.sendRedirect(resp, "/");
      return;
    }
    var sessionInfo = (SessionInfo) session.getAttribute(SessionInfo.SESSION_ATTRIBUTE_NAME);
    session.invalidate();
    if (sessionInfo == null) {
      Utils.sendRedirect(resp, "/");
      return;
    }

    State state;
    if (postLogoutRedirectPath == null || !useLogoutState) {
      state = null;
    } else {
      state = new State();
      req.getSession()
          .setAttribute(
              LogoutState.SESSION_ATTRIBUTE_NAME,
              new LogoutState(state, Utils.getReturnToParameter(req)));
    }
    var logoutRequest =
        new LogoutRequest(
            configuration.getProviderMetadata().getEndSessionEndpointURI(),
            sessionInfo.getIDToken(),
            postLogoutRedirectPath != null
                ? URI.create(req.getRequestURL().toString()).resolve(postLogoutRedirectPath)
                : null,
            state);
    Utils.sendRedirect(resp, logoutRequest.toURI().toASCIIString());
  }
}
