package net.ltgt.oidc.servlet;

import static java.util.Objects.requireNonNull;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.openid.connect.sdk.claims.LogoutTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.validators.LogoutTokenValidator;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.MalformedURLException;
import java.text.ParseException;
import java.util.Set;
import org.jspecify.annotations.Nullable;

/**
 * Implements the OpenID Connect Back-Channel Logout URI.
 *
 * <p>The OpenID Provider must support session IDs ({@code "backchannel_logout_session_supported":
 * true}). The application must have been registered to require the session ID ({@code
 * "backchannel_logout_session_required": true}).
 *
 * <p>This servlet must not be protected by authentication or CSRF protections. A {@link
 * LoggedOutSessionStore} instance must have been added as a {@link jakarta.servlet.ServletContext
 * ServletContext} attribute under the name {@link LoggedOutSessionStore#CONTEXT_ATTRIBUTE_NAME}.
 *
 * @see <a href="https://openid.net/specs/openid-connect-backchannel-1_0.html">OpenID Connect
 *     Back-Channel Logout 1.0</a>
 */
public class BackchannelLogoutServlet extends HttpServlet {
  private @Nullable Configuration configuration;
  private LoggedOutSessionStore loggedOutSessionStore;
  private LogoutTokenValidator logoutTokenValidator;

  public BackchannelLogoutServlet() {}

  /**
   * Constructs a servlet with the given configuration and logged-out session store.
   *
   * <p>When this constructor is used, the servlet context attributes won't be read.
   */
  public BackchannelLogoutServlet(
      Configuration configuration, LoggedOutSessionStore loggedOutSessionStore) {
    this.configuration = requireNonNull(configuration);
    this.loggedOutSessionStore = requireNonNull(loggedOutSessionStore);
  }

  @SuppressWarnings({"rawtypes", "unchecked"})
  @Override
  public void init() throws ServletException {
    if (loggedOutSessionStore == null) {
      loggedOutSessionStore =
          (LoggedOutSessionStore)
              getServletContext().getAttribute(LoggedOutSessionStore.CONTEXT_ATTRIBUTE_NAME);
    }
    var configuration = this.configuration;
    if (configuration == null) {
      configuration =
          (Configuration) getServletContext().getAttribute(Configuration.CONTEXT_ATTRIBUTE_NAME);
    }
    requireNonNull(loggedOutSessionStore, "loggedOutSessionStore");
    requireNonNull(configuration, "configuration");
    try {
      logoutTokenValidator =
          new LogoutTokenValidator(
              configuration.getProviderMetadata().getIssuer(),
              configuration.getClientAuthentication().getClientID(),
              false, // XXX: make configurable?
              new JWSVerificationKeySelector(
                  Set.copyOf(configuration.getProviderMetadata().getIDTokenJWSAlgs()),
                  JWKSourceBuilder.create(
                          configuration.getProviderMetadata().getJWKSetURI().toURL())
                      .build()),
              null);
    } catch (MalformedURLException e) {
      throw new ServletException(e);
    }
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException, IOException {
    // XXX: validate req.getContentType() ?
    var logoutTokenParam = req.getParameter("logout_token");
    if (logoutTokenParam == null) {
      sendError(resp, "Missing logout token", null);
      return;
    }
    JWT logoutToken;
    try {
      logoutToken = JWTParser.parse(logoutTokenParam);
    } catch (ParseException e) {
      sendError(resp, "Error parsing logout token", e);
      return;
    }
    LogoutTokenClaimsSet logoutTokenClaims;
    try {
      logoutTokenClaims = logoutTokenValidator.validate(logoutToken);
    } catch (BadJOSEException e) {
      sendError(resp, "Error validating logout token", e);
      return;
    } catch (JOSEException e) {
      sendError(resp, "Invalid logout token", e);
      return;
    }

    loggedOutSessionStore.logout(logoutTokenClaims.getSessionID());

    resp.setHeader("Cache-Control", "no-store");
    resp.setStatus(HttpServletResponse.SC_OK);
  }

  private void sendError(HttpServletResponse resp, String message, @Nullable Throwable cause)
      throws IOException {
    if (cause != null) {
      log(message, cause);
    }
    resp.sendError(HttpServletResponse.SC_BAD_REQUEST, message);
  }
}
