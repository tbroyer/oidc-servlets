package net.ltgt.oidc.servlet;

import static java.util.Objects.requireNonNull;

import com.google.errorprone.annotations.OverridingMethodsMustInvokeSuper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.source.JWKSource;
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
 * <p>If a {@link JWKSource} instance has been added as {@link jakarta.servlet.ServletContext
 * ServletContext} attribute under the name {@link Utils#JWK_SOURCE_CONTEXT_ATTRIBUTE_NAME}, it'll
 * be used to validate the logout token signature.
 *
 * @see <a href="https://openid.net/specs/openid-connect-backchannel-1_0.html">OpenID Connect
 *     Back-Channel Logout 1.0</a>
 */
public class BackchannelLogoutServlet extends HttpServlet {
  private final @Nullable Configuration configuration;
  private LoggedOutSessionStore loggedOutSessionStore;
  private final @Nullable JWKSource<?> jwkSource;
  private LogoutTokenValidator logoutTokenValidator;

  public BackchannelLogoutServlet() {
    this.configuration = null;
    this.jwkSource = null;
  }

  /**
   * Constructs a servlet with the given configuration and logged-out session store.
   *
   * <p>When this constructor is used, the servlet context attributes for the configuration and
   * logged-out session store won't be read. The JWK source will however be read from the servlet
   * context, and a default value based on the configuration's JWKSet URI possibly be provided to
   * the servlet context.
   */
  public BackchannelLogoutServlet(
      Configuration configuration, LoggedOutSessionStore loggedOutSessionStore) {
    this.configuration = requireNonNull(configuration);
    this.loggedOutSessionStore = requireNonNull(loggedOutSessionStore);
    this.jwkSource = null;
  }

  /**
   * Constructs a servlet with the given configuration, logged-out session store, and JWK source.
   *
   * <p>When this constructor is used, the servlet context attributes won't be read.
   */
  public BackchannelLogoutServlet(
      Configuration configuration,
      LoggedOutSessionStore loggedOutSessionStore,
      JWKSource<?> jwkSource) {
    this.configuration = requireNonNull(configuration);
    this.loggedOutSessionStore = requireNonNull(loggedOutSessionStore);
    this.jwkSource = requireNonNull(jwkSource);
  }

  @SuppressWarnings({"rawtypes", "unchecked"})
  @OverridingMethodsMustInvokeSuper
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
    JWKSource<?> jwkSource = this.jwkSource;
    if (jwkSource == null) {
      jwkSource =
          Utils.getJWKSource(
              getServletContext(), configuration.getProviderMetadata().getJWKSetURI());
    }
    requireNonNull(loggedOutSessionStore, "loggedOutSessionStore");
    requireNonNull(configuration, "configuration");
    requireNonNull(jwkSource, "jwkSource");
    logoutTokenValidator =
        new LogoutTokenValidator(
            configuration.getProviderMetadata().getIssuer(),
            configuration.getClientId(),
            false, // XXX: make configurable?
            new JWSVerificationKeySelector(
                Set.copyOf(configuration.getProviderMetadata().getIDTokenJWSAlgs()), jwkSource),
            null);
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
