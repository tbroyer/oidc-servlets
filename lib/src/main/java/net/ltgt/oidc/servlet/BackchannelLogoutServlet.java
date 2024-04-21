package net.ltgt.oidc.servlet;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.openid.connect.sdk.claims.LogoutTokenClaimsSet;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.MalformedURLException;
import java.text.ParseException;
import java.util.Set;
import org.checkerframework.checker.nullness.qual.Nullable;

public class BackchannelLogoutServlet extends HttpServlet {
  private LoggedOutSessionStore loggedOutSessionStore;
  private LogoutTokenValidator logoutTokenValidator;

  @SuppressWarnings({"rawtypes", "unchecked"})
  @Override
  public void init() throws ServletException {
    loggedOutSessionStore =
        (LoggedOutSessionStore)
            getServletContext().getAttribute(LoggedOutSessionStore.CONTEXT_ATTRIBUTE_NAME);
    Configuration configuration =
        (Configuration) getServletContext().getAttribute(Configuration.CONTEXT_ATTRIBUTE_NAME);
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
