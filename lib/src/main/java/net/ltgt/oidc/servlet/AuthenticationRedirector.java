package net.ltgt.oidc.servlet;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URI;

public class AuthenticationRedirector {
  public static final String CONTEXT_ATTRIBUTE_NAME = AuthenticationRedirector.class.getName();

  private final Configuration configuration;
  private final String callbackPath;

  public AuthenticationRedirector(Configuration configuration, String callbackPath) {
    this.configuration = configuration;
    this.callbackPath = callbackPath;
  }

  void redirectToAuthenticationEndpoint(
      HttpServletRequest req, HttpServletResponse res, String returnTo) {
    State state = new State();
    Nonce nonce = new Nonce();
    CodeVerifier codeVerifier = new CodeVerifier();
    req.getSession()
        .setAttribute(
            AuthenticationState.SESSION_ATTRIBUTE_NAME,
            new AuthenticationState(state, nonce, codeVerifier, returnTo));
    AuthenticationRequest.Builder authenticationRequestBuilder =
        new AuthenticationRequest.Builder(
            ResponseType.CODE,
            new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.PROFILE, OIDCScopeValue.EMAIL),
            configuration.clientAuthentication().getClientID(),
            URI.create(req.getRequestURL().toString()).resolve(callbackPath));
    authenticationRequestBuilder
        .endpointURI(configuration.providerMetadata().getAuthorizationEndpointURI())
        .state(state)
        .nonce(nonce)
        // From RFC: If the client is capable of using S256, it MUST use S256.
        .codeChallenge(codeVerifier, CodeChallengeMethod.S256);
    Utils.sendRedirect(res, authenticationRequestBuilder.build().toURI().toASCIIString());
  }
}
