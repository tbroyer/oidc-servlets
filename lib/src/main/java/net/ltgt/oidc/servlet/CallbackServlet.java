package net.ltgt.oidc.servlet;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.JakartaServletUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import org.checkerframework.checker.nullness.qual.Nullable;

public class CallbackServlet extends HttpServlet {

  private Configuration configuration;
  private IDTokenValidator idTokenValidator;

  @SuppressWarnings({"rawtypes", "unchecked"})
  @Override
  public void init() throws ServletException {
    configuration =
        (Configuration) getServletContext().getAttribute(Configuration.CONTEXT_ATTRIBUTE_NAME);
    try {
      idTokenValidator =
          new IDTokenValidator(
              configuration.providerMetadata().getIssuer(),
              configuration.clientAuthentication().getClientID(),
              new JWSVerificationKeySelector(
                  Set.copyOf(configuration.providerMetadata().getIDTokenJWSAlgs()),
                  JWKSourceBuilder.create(configuration.providerMetadata().getJWKSetURI().toURL())
                      .build()),
              null);
    } catch (MalformedURLException e) {
      throw new ServletException(e);
    }
  }

  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException, IOException {
    doPost(req, resp);
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException, IOException {
    if (!Utils.isNavigation(req)) {
      sendError(resp, HttpServletResponse.SC_BAD_REQUEST, "Not a navigation request", null);
    }
    AuthenticationResponse response;
    try {
      response = AuthenticationResponseParser.parse(JakartaServletUtils.createHTTPRequest(req));
    } catch (ParseException e) {
      sendError(resp, HttpServletResponse.SC_BAD_REQUEST, "Error parsing parameters", e);
      return;
    }
    var authenticationState =
        Optional.ofNullable(req.getSession(false))
            .map(
                session ->
                    (AuthenticationState)
                        session.getAttribute(AuthenticationState.SESSION_ATTRIBUTE_NAME))
            .orElse(null);
    if (authenticationState == null) {
      sendError(
          resp,
          HttpServletResponse.SC_BAD_REQUEST,
          "Missing saved state from authorization request initiation",
          null);
      return;
    }
    if (!Objects.equals(response.getState(), authenticationState.state())) {
      sendError(resp, HttpServletResponse.SC_BAD_REQUEST, "State mismatch", null);
      return;
    }
    if (!response.indicatesSuccess()) {
      sendError(
          resp,
          HttpServletResponse.SC_BAD_REQUEST,
          response.toErrorResponse().getErrorObject().getCode(),
          null);
      return;
    }
    var code = response.toSuccessResponse().getAuthorizationCode();
    var tokenRequest =
        new TokenRequest(
            configuration.providerMetadata().getTokenEndpointURI(),
            configuration.clientAuthentication(),
            new AuthorizationCodeGrant(
                code,
                URI.create(req.getRequestURL().toString()),
                authenticationState.codeVerifier()));
    TokenResponse tokenResponse;
    try {
      tokenResponse = OIDCTokenResponseParser.parse(tokenRequest.toHTTPRequest().send());
    } catch (ParseException | IOException e) {
      sendError(resp, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error in token request", e);
      return;
    }
    if (!tokenResponse.indicatesSuccess()) {
      sendError(
          resp,
          HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
          "Token request returned error: " + tokenResponse.toErrorResponse().getErrorObject(),
          null);
      return;
    }
    var successResponse = (OIDCTokenResponse) tokenResponse.toSuccessResponse();

    IDTokenClaimsSet idTokenClaims;
    try {
      idTokenClaims =
          idTokenValidator.validate(
              successResponse.getOIDCTokens().getIDToken(), authenticationState.nonce());
    } catch (BadJOSEException e) {
      sendError(resp, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error validating ID Token", e);
      return;
    } catch (JOSEException e) {
      sendError(resp, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Invalid ID Token", e);
      return;
    }

    var userInfoRequest =
        new UserInfoRequest(
            configuration.providerMetadata().getUserInfoEndpointURI(),
            successResponse.getOIDCTokens().getAccessToken());
    UserInfoResponse userInfoResponse;
    try {
      userInfoResponse = UserInfoResponse.parse(userInfoRequest.toHTTPRequest().send());
    } catch (ParseException | IOException e) {
      sendError(
          resp, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error in User Info request", e);
      return;
    }
    if (!userInfoResponse.indicatesSuccess()) {
      sendError(
          resp,
          HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
          "User Info request returned error: "
              + userInfoResponse.toErrorResponse().getErrorObject().getCode(),
          null);
      return;
    }

    var userInfo = userInfoResponse.toSuccessResponse().getUserInfo();
    if (userInfo == null) {
      try {
        userInfo =
            new UserInfo(userInfoResponse.toSuccessResponse().getUserInfoJWT().getJWTClaimsSet());
      } catch (java.text.ParseException e) {
        sendError(
            resp, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error parsing ID Token claims", e);
        return;
      }
    }
    req.changeSessionId();
    req.getSession()
        .setAttribute(
            SessionInfo.SESSION_ATTRIBUTE_NAME,
            new SessionInfo(successResponse.getOIDCTokens(), idTokenClaims, userInfo));
    Utils.sendRedirect(resp, authenticationState.requestUri());
  }

  private void sendError(
      HttpServletResponse resp, int statusCode, String message, @Nullable Throwable cause)
      throws IOException {
    if (cause != null) {
      log(message, cause);
    }
    resp.sendError(statusCode, message);
  }
}
