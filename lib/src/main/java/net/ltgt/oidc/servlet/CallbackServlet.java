package net.ltgt.oidc.servlet;

import static java.util.Objects.requireNonNull;

import com.google.errorprone.annotations.ForOverride;
import com.google.errorprone.annotations.OverridingMethodsMustInvokeSuper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ErrorResponse;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Request;
import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequestSender;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.util.URLUtils;
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
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.jspecify.annotations.Nullable;

/**
 * Implements the OpenID Connect Redirect URI for the <a
 * href="https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth">authorization code
 * flow</a>.
 *
 * <p>A {@link Configuration} instance must have been added as a {@link
 * jakarta.servlet.ServletContext ServletContext} attribute under the name {@link
 * Configuration#CONTEXT_ATTRIBUTE_NAME}.
 *
 * <p>If a {@link HTTPRequestSender} instance has been added as {@link
 * jakarta.servlet.ServletContext ServletContext} attribute under the name {@link
 * Utils#HTTP_REQUEST_SENDER_CONTEXT_ATTRIBUTE_NAME}, it'll be used to send requests to the OpenID
 * Provider.
 *
 * <p>If a {@link JWKSource} instance has been added as {@link jakarta.servlet.ServletContext
 * ServletContext} attribute under the name {@link Utils#JWK_SOURCE_CONTEXT_ATTRIBUTE_NAME}, it'll
 * be used to validate the ID Token signature.
 *
 * <p>Authentication state must have been put in the {@linkplain jakarta.servlet.http.HttpSession
 * session} by an {@link AuthenticationRedirector} (generally through the {@link LoginServlet} or an
 * {@linkplain AbstractAuthorizationFilter authorization filter}).
 *
 * <p>After validating the request, and if authentication was successful, the user will be
 * redirected to the page stored in the authentication state.
 *
 * <p>If a {@link UserPrincipalFactory} is available in the {@link jakarta.servlet.ServletContext
 * ServletContext}, it'll be called to possibly load additional data to the session, that can later
 * be made available through the {@link UserPrincipal}.
 *
 * <p>If an {@link OAuthTokensHandler} is available in the {@link jakarta.servlet.ServletContext
 * ServletContext}, it'll be called to possibly store the OAuth tokens in the session for later use
 * to access protected resources. Otherwise, a {@link RevokingOAuthTokensHandler} will immediately
 * revoke the tokens so they're unusable in case they leak somehow.
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect Core 1.0</a>
 */
public class CallbackServlet extends HttpServlet {
  public static final String ERROR_NOT_A_NAVIGATION = "not_a_navigation";
  public static final String ERROR_PARSING_PARAMETERS = "error_parsing_parameters";

  private Configuration configuration;
  private UserPrincipalFactory userPrincipalFactory;
  private @Nullable HTTPRequestSender httpRequestSender;
  private boolean httpRequestSenderExplicitlySet;
  private OAuthTokensHandler oauthTokensHandler;
  private final @Nullable JWKSource<?> jwkSource;
  private @Nullable DPoPSupport dpopSupport;
  private boolean dpopSupportExplicitlySet;
  private @Nullable DPoPNonceStore dpopNonceStore;
  private IDTokenValidator idTokenValidator;

  public CallbackServlet() {
    this.jwkSource = null;
  }

  /**
   * Constructs a servlet with the given configuration and {@link UserPrincipal} factory, no HTTP
   * request sender, no DPoP support, and a default OAuth tokens handler.
   *
   * <p>When this constructor is used, the servlet context attributes for the configuration, {@link
   * UserPrincipal} factory, HTTP request sender, and OAuth tokens handler won't be read. The JWK
   * source will however be read from the servlet context, and a default value based on the
   * configuration's JWKSet URI possibly be provided to the servlet context.
   *
   * <p>This is equivalent to {@code new CallbackServlet(configuration, userPrincipalFactory, new
   * RevokingOAuthTokensHandler(configuration))}.
   */
  public CallbackServlet(Configuration configuration, UserPrincipalFactory userPrincipalFactory) {
    this(configuration, userPrincipalFactory, new RevokingOAuthTokensHandler(configuration));
  }

  /**
   * Constructs a servlet with the given configuration, {@link UserPrincipal} factory, and OAuth
   * tokens handler, and no HTTP request sender or DPoP support.
   *
   * <p>When this constructor is used, the servlet context attributes for the configuration, {@link
   * UserPrincipal} factory, HTTP request sender, and OAuth tokens handler won't be read. The JWK
   * source will however be read from the servlet context, and a default value based on the
   * configuration's JWKSet URI possibly be provided to the servlet context.
   *
   * <p>This is equivalent to {@code new CallbackServlet(configuration, userPrincipalFactory,
   * oauthTokensHandler, null)}.
   */
  public CallbackServlet(
      Configuration configuration,
      UserPrincipalFactory userPrincipalFactory,
      OAuthTokensHandler oauthTokensHandler) {
    this(configuration, userPrincipalFactory, oauthTokensHandler, null);
  }

  /**
   * Constructs a servlet with the given configuration, {@link UserPrincipal} factory, and HTTP
   * request sender, a default OAuth tokens handler, and no DPoP support.
   *
   * <p>When this constructor is used, the servlet context attributes for the configuration, {@link
   * UserPrincipal} factory, HTTP request sender, and OAuth tokens handler won't be read. The JWK
   * source will however be read from the servlet context, and a default value based on the
   * configuration's JWKSet URI possibly be provided to the servlet context.
   *
   * <p>This is equivalent to {@code new CallbackServlet(configuration, userPrincipalFactory, new
   * RevokingOAuthTokensHandler(configuration), httpRequestSender)}.
   */
  public CallbackServlet(
      Configuration configuration,
      UserPrincipalFactory userPrincipalFactory,
      @Nullable HTTPRequestSender httpRequestSender) {
    this(
        configuration,
        userPrincipalFactory,
        new RevokingOAuthTokensHandler(configuration),
        httpRequestSender);
  }

  /**
   * Constructs a servlet with the given configuration, {@link UserPrincipal} factory, OAuth tokens
   * handler, and HTTP request sender, and no DPoP support.
   *
   * <p>When this constructor is used, the servlet context attributes for the configuration, {@link
   * UserPrincipal} factory, HTTP request sender, and OAuth tokens handler won't be read. The JWK
   * source will however be read from the servlet context, and a default value based on the
   * configuration's JWKSet URI possibly be provided to the servlet context.
   */
  public CallbackServlet(
      Configuration configuration,
      UserPrincipalFactory userPrincipalFactory,
      OAuthTokensHandler oauthTokensHandler,
      @Nullable HTTPRequestSender httpRequestSender) {
    this.configuration = requireNonNull(configuration);
    this.userPrincipalFactory = requireNonNull(userPrincipalFactory);
    this.jwkSource = null;
    this.oauthTokensHandler = requireNonNull(oauthTokensHandler);
    this.httpRequestSender = httpRequestSender;
    this.httpRequestSenderExplicitlySet = true;
    this.dpopSupport = null;
    this.dpopSupportExplicitlySet = true;
    this.dpopNonceStore = null;
  }

  /**
   * Constructs a servlet with the given configuration {@link UserPrincipal} factory, and DPoP
   * support with optional nonce store, no HTTP request sender, and a default OAuth tokens handler.
   *
   * <p>When this constructor is used, the servlet context attributes for the configuration, {@link
   * UserPrincipal} factory, HTTP request sender, and OAuth tokens handler won't be read. The JWK
   * source will however be read from the servlet context, and a default value based on the
   * configuration's JWKSet URI possibly be provided to the servlet context.
   *
   * <p>This is equivalent to {@code new CallbackServlet(configuration, userPrincipalFactory, new
   * RevokingOAuthTokensHandler(configuration), dpopSupport, dpopNonceStore)}.
   */
  public CallbackServlet(
      Configuration configuration,
      UserPrincipalFactory userPrincipalFactory,
      DPoPSupport dpopSupport,
      @Nullable DPoPNonceStore dpopNonceStore) {
    this(
        configuration,
        userPrincipalFactory,
        new RevokingOAuthTokensHandler(configuration),
        dpopSupport,
        dpopNonceStore);
  }

  /**
   * Constructs a servlet with the given configuration, {@link UserPrincipal} factory, OAuth tokens
   * handler, and DPoP support with optional nonce store, and no HTTP request sender.
   *
   * <p>When this constructor is used, the servlet context attributes for the configuration, {@link
   * UserPrincipal} factory, HTTP request sender, and OAuth tokens handler won't be read. The JWK
   * source will however be read from the servlet context, and a default value based on the
   * configuration's JWKSet URI possibly be provided to the servlet context.
   *
   * <p>This is equivalent to {@code new CallbackServlet(configuration, userPrincipalFactory,
   * oauthTokensHandler, null, dpopSupport, dpopNonceStore)}.
   */
  public CallbackServlet(
      Configuration configuration,
      UserPrincipalFactory userPrincipalFactory,
      OAuthTokensHandler oauthTokensHandler,
      DPoPSupport dpopSupport,
      @Nullable DPoPNonceStore dpopNonceStore) {
    this(
        configuration, userPrincipalFactory, oauthTokensHandler, null, dpopSupport, dpopNonceStore);
  }

  /**
   * Constructs a servlet with the given configuration, {@link UserPrincipal} factory, HTTP request
   * sender, DPoP support with optional nonce store, and a default OAuth tokens handler.
   *
   * <p>When this constructor is used, the servlet context attributes for the configuration, {@link
   * UserPrincipal} factory, HTTP request sender, and OAuth tokens handler won't be read. The JWK
   * source will however be read from the servlet context, and a default value based on the
   * configuration's JWKSet URI possibly be provided to the servlet context.
   *
   * <p>This is equivalent to {@code new CallbackServlet(configuration, userPrincipalFactory, new
   * RevokingOAuthTokensHandler(configuration), httpRequestHandler, dpopSupport, dpopNonceStore)}.
   */
  public CallbackServlet(
      Configuration configuration,
      UserPrincipalFactory userPrincipalFactory,
      @Nullable HTTPRequestSender httpRequestSender,
      DPoPSupport dpopSupport,
      @Nullable DPoPNonceStore dpopNonceStore) {
    this(
        configuration,
        userPrincipalFactory,
        new RevokingOAuthTokensHandler(configuration),
        httpRequestSender,
        dpopSupport,
        dpopNonceStore);
  }

  /**
   * Constructs a servlet with the given configuration, {@link UserPrincipal} factory, HTTP request
   * sender, OAuth tokens handler, and DPoP support with optional nonce store.
   *
   * <p>When this constructor is used, the servlet context attributes for the configuration, {@link
   * UserPrincipal} factory, HTTP request sender, and OAuth tokens handler won't be read. The JWK
   * source will however be read from the servlet context, and a default value based on the
   * configuration's JWKSet URI possibly be provided to the servlet context.
   */
  public CallbackServlet(
      Configuration configuration,
      UserPrincipalFactory userPrincipalFactory,
      OAuthTokensHandler oauthTokensHandler,
      @Nullable HTTPRequestSender httpRequestSender,
      DPoPSupport dpopSupport,
      @Nullable DPoPNonceStore dpopNonceStore) {
    this.configuration = requireNonNull(configuration);
    this.userPrincipalFactory = requireNonNull(userPrincipalFactory);
    this.jwkSource = null;
    this.oauthTokensHandler = requireNonNull(oauthTokensHandler);
    this.httpRequestSender = httpRequestSender;
    this.httpRequestSenderExplicitlySet = true;
    this.dpopSupport = requireNonNull(dpopSupport);
    this.dpopSupportExplicitlySet = true;
    this.dpopNonceStore = dpopNonceStore;
  }

  /**
   * Constructs a servlet with the given configuration, {@link UserPrincipal} factory, HTTP request
   * sender, JWK source, and OAuth tokens handler, and no DPoP support.
   *
   * <p>When this constructor is used, the servlet context attributes won't be read.
   */
  public CallbackServlet(
      Configuration configuration,
      UserPrincipalFactory userPrincipalFactory,
      JWKSource<?> jwkSource,
      OAuthTokensHandler oauthTokensHandler,
      @Nullable HTTPRequestSender httpRequestSender) {
    this.configuration = requireNonNull(configuration);
    this.userPrincipalFactory = requireNonNull(userPrincipalFactory);
    this.jwkSource = requireNonNull(jwkSource);
    this.oauthTokensHandler = requireNonNull(oauthTokensHandler);
    this.httpRequestSender = httpRequestSender;
    this.httpRequestSenderExplicitlySet = true;
    this.dpopSupport = null;
    this.dpopSupportExplicitlySet = true;
    this.dpopNonceStore = null;
  }

  /**
   * Constructs a servlet with the given configuration, {@link UserPrincipal} factory, HTTP request
   * sender, JWK source, OAuth tokens handler, and DPoP support with optional nonce store.
   *
   * <p>When this constructor is used, the servlet context attributes won't be read.
   */
  public CallbackServlet(
      Configuration configuration,
      UserPrincipalFactory userPrincipalFactory,
      JWKSource<?> jwkSource,
      OAuthTokensHandler oauthTokensHandler,
      @Nullable HTTPRequestSender httpRequestSender,
      DPoPSupport dpopSupport,
      @Nullable DPoPNonceStore dpopNonceStore) {
    this.configuration = requireNonNull(configuration);
    this.userPrincipalFactory = requireNonNull(userPrincipalFactory);
    this.jwkSource = requireNonNull(jwkSource);
    this.oauthTokensHandler = requireNonNull(oauthTokensHandler);
    this.httpRequestSender = httpRequestSender;
    this.httpRequestSenderExplicitlySet = true;
    this.dpopSupport = requireNonNull(dpopSupport);
    this.dpopSupportExplicitlySet = true;
    this.dpopNonceStore = dpopNonceStore;
  }

  @SuppressWarnings({"rawtypes", "unchecked"})
  @OverridingMethodsMustInvokeSuper
  @Override
  public void init() throws ServletException {
    if (configuration == null) {
      configuration =
          (Configuration) getServletContext().getAttribute(Configuration.CONTEXT_ATTRIBUTE_NAME);
    }
    requireNonNull(configuration, "configuration");
    if (userPrincipalFactory == null) {
      userPrincipalFactory =
          (UserPrincipalFactory)
              getServletContext().getAttribute(UserPrincipalFactory.CONTEXT_ATTRIBUTE_NAME);
    }
    if (userPrincipalFactory == null) {
      userPrincipalFactory = SimpleUserPrincipal.FACTORY;
    }
    if (!httpRequestSenderExplicitlySet) {
      assert httpRequestSender == null;
      httpRequestSender =
          (HTTPRequestSender)
              getServletContext().getAttribute(Utils.HTTP_REQUEST_SENDER_CONTEXT_ATTRIBUTE_NAME);
    }
    if (oauthTokensHandler == null) {
      oauthTokensHandler =
          (OAuthTokensHandler)
              getServletContext().getAttribute(OAuthTokensHandler.CONTEXT_ATTRIBUTE_NAME);
    }
    if (oauthTokensHandler == null) {
      oauthTokensHandler = new RevokingOAuthTokensHandler(configuration, httpRequestSender);
    }
    if (!dpopSupportExplicitlySet) {
      assert dpopSupport == null && dpopNonceStore == null;
      dpopSupport =
          (DPoPSupport) getServletContext().getAttribute(DPoPSupport.CONTEXT_ATTRIBUTE_NAME);
      dpopNonceStore =
          (DPoPNonceStore) getServletContext().getAttribute(DPoPNonceStore.CONTEXT_ATTRIBUTE_NAME);
      if (dpopNonceStore != null) {
        requireNonNull(dpopSupport, "DPoP nonce store is useless without DPoP support");
      }
    }
    if (dpopNonceStore == null && dpopSupport != null) {
      dpopNonceStore = new PerUriDPoPNonceStore();
    }
    JWKSource<?> jwkSource = this.jwkSource;
    if (jwkSource == null) {
      jwkSource =
          Utils.getJWKSource(
              getServletContext(), configuration.getProviderMetadata().getJWKSetURI());
    }
    idTokenValidator =
        new IDTokenValidator(
            configuration.getProviderMetadata().getIssuer(),
            configuration.getClientId(),
            new JWSVerificationKeySelector(
                Set.copyOf(configuration.getProviderMetadata().getIDTokenJWSAlgs()), jwkSource),
            null);
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
      sendRedirectToError(req, resp, ERROR_NOT_A_NAVIGATION, "Not a navigation request", null);
      return;
    }
    AuthenticationResponse response;
    try {
      response =
          AuthenticationResponseParser.parse(
              URI.create(req.getRequestURL().toString()),
              req.getParameterMap().entrySet().stream()
                  .collect(
                      Collectors.toUnmodifiableMap(
                          Map.Entry::getKey, entry -> Arrays.asList(entry.getValue()))));
    } catch (ParseException e) {
      sendRedirectToError(req, resp, ERROR_PARSING_PARAMETERS, "Error parsing parameters", e);
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
    var session = req.getSession(false);
    var code = response.toSuccessResponse().getAuthorizationCode();
    if (code == null) {
      // Might be a browser swapping attack switching to fragment response mode
      sendRedirectToError(req, resp, ERROR_PARSING_PARAMETERS, "Error parsing parameters", null);
      return;
    }
    var authenticationState =
        Optional.ofNullable(session)
            .map(
                session_ -> {
                  var state =
                      (AuthenticationState)
                          session_.getAttribute(AuthenticationState.SESSION_ATTRIBUTE_NAME);
                  session_.removeAttribute(AuthenticationState.SESSION_ATTRIBUTE_NAME);
                  return state;
                })
            .orElse(null);
    // Do not check authentication state yet; exchange code first to prevent browser swapping attack
    // If the authentication state is missing, the PKCE code verifier will be missing as well, and
    // this should invalidate the authorization code
    var tokenRequest =
        new TokenRequest.Builder(
                configuration.getProviderMetadata().getTokenEndpointURI(),
                configuration.getClientAuthenticationSupplier().getClientAuthentication(),
                new AuthorizationCodeGrant(
                    code,
                    URI.create(req.getRequestURL().toString()),
                    authenticationState == null ? null : authenticationState.codeVerifier()))
            .build();
    TokenResponse tokenResponse;
    try {
      tokenResponse = send(session, tokenRequest);
    } catch (ParseException | IOException | JOSEException e) {
      sendError(resp, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error in token request", e);
      return;
    }
    // Now that we "used" the authorization code, we can check the authentication state for CSRF
    if (authenticationState == null) {
      maybeRevokeTokens(tokenResponse);
      sendError(
          resp,
          HttpServletResponse.SC_BAD_REQUEST,
          "Missing saved state from authorization request initiation",
          null);
      return;
    }
    if (!Objects.equals(response.getState(), authenticationState.state())) {
      maybeRevokeTokens(tokenResponse);
      sendError(resp, HttpServletResponse.SC_BAD_REQUEST, "State mismatch", null);
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
    assert session != null;

    IDTokenClaimsSet idTokenClaims;
    try {
      idTokenClaims =
          idTokenValidator.validate(
              successResponse.getOIDCTokens().getIDToken(), authenticationState.nonce());
    } catch (BadJOSEException e) {
      revokeTokens(successResponse);
      sendError(resp, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error validating ID Token", e);
      return;
    } catch (JOSEException e) {
      revokeTokens(successResponse);
      sendError(resp, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Invalid ID Token", e);
      return;
    }

    var userInfoRequest =
        new UserInfoRequest(
            configuration.getProviderMetadata().getUserInfoEndpointURI(),
            successResponse.getOIDCTokens().getAccessToken());
    UserInfoResponse userInfoResponse;
    try {
      userInfoResponse = send(session, userInfoRequest);
    } catch (ParseException | IOException | JOSEException e) {
      revokeTokens(successResponse);
      sendError(
          resp, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error in User Info request", e);
      return;
    }
    if (!userInfoResponse.indicatesSuccess()) {
      // Error might be because the token is wrong for some reason, but better be safe than sorry
      revokeTokens(successResponse);
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
        revokeTokens(successResponse);
        sendError(
            resp, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error parsing ID Token claims", e);
        return;
      }
    }
    req.changeSessionId();
    var sessionInfo =
        new SessionInfo(successResponse.getOIDCTokens().getIDToken(), idTokenClaims, userInfo);
    session.setAttribute(SessionInfo.SESSION_ATTRIBUTE_NAME, sessionInfo);
    userPrincipalFactory.userAuthenticated(sessionInfo, session);
    oauthTokensHandler.tokensAcquired(successResponse, session);
    Utils.sendRedirect(resp, authenticationState.requestUri());
  }

  private TokenResponse send(@Nullable HttpSession session, TokenRequest tokenRequest)
      throws IOException, JOSEException, ParseException {
    return send(
        session,
        tokenRequest,
        null,
        OIDCTokenResponseParser::parse,
        TokenResponse::toErrorResponse);
  }

  private UserInfoResponse send(HttpSession session, UserInfoRequest userInfoRequest)
      throws IOException, JOSEException, ParseException {
    return send(
        session,
        userInfoRequest,
        userInfoRequest.getAccessToken(),
        UserInfoResponse::parse,
        UserInfoResponse::toErrorResponse);
  }

  @FunctionalInterface
  private interface ResponseParser<R extends Response> {
    R parse(HTTPResponse response) throws ParseException;
  }

  private <R extends Response> R send(
      @Nullable HttpSession session,
      Request request,
      @Nullable AccessToken accessToken,
      ResponseParser<R> responseParser,
      Function<R, ErrorResponse> toErrorResponse)
      throws IOException, JOSEException, ParseException {
    var httpRequest = request.toHTTPRequest();
    // If there's no point in using DPoP if there's no session
    // Absence of a session only happens to exchange an auth code in a browser swapping attack,
    // where the request is expected to fail anyway.
    if (dpopSupport != null && session != null) {
      var nonce = requireNonNull(dpopNonceStore).getNonce(httpRequest.getURI());
      var proofFactory = dpopSupport.getProofFactory(session);
      httpRequest.setDPoP(
          proofFactory.createDPoPJWT(
              httpRequest.getMethod().toString(), httpRequest.getURI(), accessToken, nonce));
      var httpResponse = send(httpRequest);
      nonce = httpResponse.getDPoPNonce();
      var response = responseParser.parse(httpResponse);
      if (response.indicatesSuccess()
          || !OAuth2Error.USE_DPOP_NONCE.equals(toErrorResponse.apply(response).getErrorObject())) {
        return response;
      }
      httpRequest.setDPoP(
          proofFactory.createDPoPJWT(
              httpRequest.getMethod().toString(), httpRequest.getURI(), accessToken, nonce));
      // fall-through to repeat the httpRequest with the new DPoP including the nonce
    }
    return responseParser.parse(send(httpRequest));
  }

  private HTTPResponse send(HTTPRequest request) throws IOException {
    HTTPResponse httpResponse;
    if (httpRequestSender != null) {
      httpResponse = request.send(httpRequestSender);
    } else {
      httpResponse = request.send();
    }
    if (dpopSupport != null) {
      var nonce = httpResponse.getDPoPNonce();
      if (nonce != null) {
        requireNonNull(dpopNonceStore).setNonce(request.getURI(), nonce);
      }
    }
    return httpResponse;
  }

  private void maybeRevokeTokens(TokenResponse response) {
    if (response.indicatesSuccess()) {
      revokeTokens((OIDCTokenResponse) response.toSuccessResponse());
    }
  }

  private void revokeTokens(OIDCTokenResponse response) {
    new RevokingOAuthTokensHandler(configuration, httpRequestSender) {
      @Override
      protected void handleError(Exception e) {
        log("Error revoking the access token after an error", e);
      }
    }.revokeAsync(response.getTokens().getAccessToken());
  }

  @ForOverride
  protected void sendError(
      HttpServletResponse resp, int statusCode, String message, @Nullable Throwable cause)
      throws IOException, ServletException {
    if (cause != null) {
      log(message, cause);
    }
    resp.sendError(statusCode, message);
  }

  @ForOverride
  protected void sendRedirectToError(
      HttpServletRequest req,
      HttpServletResponse resp,
      String error,
      String message,
      @Nullable Throwable cause)
      throws IOException, ServletException {
    if (cause != null) {
      log(message, cause);
    }
    var params =
        URLUtils.serializeParameters(
            Map.of("error", List.of(error), "error_description", List.of(message)));
    // Must include a #hash to replace any response_mode=fragment response that could leak an
    // authorization code through XSS
    Utils.sendRedirect(resp, req.getRequestURI() + "?" + params + "#" + params);
  }
}
