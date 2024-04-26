package net.ltgt.oidc.servlet;

import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.LogoutRequest;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import org.checkerframework.checker.nullness.qual.Nullable;

public class LogoutServlet extends HttpServlet {
  public static final String POST_LOGOUT_REDIRECT_PATH = "post-logout-redirect-path";
  public static final String USE_LOGOUT_STATE = "use-logout-state";

  private Configuration configuration;
  private @Nullable String postLogoutRedirectPath;
  private Boolean useLogoutState;

  public LogoutServlet() {}

  public LogoutServlet(String postLogoutRedirectPath) {
    this(postLogoutRedirectPath, false);
  }

  public LogoutServlet(String postLogoutRedirectPath, boolean useLogoutState) {
    this.postLogoutRedirectPath = postLogoutRedirectPath;
    this.useLogoutState = useLogoutState;
  }

  @Override
  public void init() throws ServletException {
    configuration =
        (Configuration) getServletContext().getAttribute(Configuration.CONTEXT_ATTRIBUTE_NAME);
    if (postLogoutRedirectPath == null) {
      postLogoutRedirectPath = getInitParameter(POST_LOGOUT_REDIRECT_PATH);
    }
    if (useLogoutState == null) {
      useLogoutState = Boolean.parseBoolean(getInitParameter(USE_LOGOUT_STATE));
    }
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
            sessionInfo.getOIDCTokens().getIDToken(),
            postLogoutRedirectPath != null
                ? URI.create(req.getRequestURL().toString()).resolve(postLogoutRedirectPath)
                : null,
            state);
    Utils.sendRedirect(resp, logoutRequest.toURI().toASCIIString());
  }
}
