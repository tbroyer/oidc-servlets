package net.ltgt.oidc.servlet.example.jetty;

import com.google.errorprone.annotations.ForOverride;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;

public abstract class AbstractAuthorizationFilter extends HttpFilter {

  private Configuration configuration;

  @Override
  public void init() throws ServletException {
    configuration =
        (Configuration) getServletContext().getAttribute(Configuration.CONTEXT_ATTRIBUTE_NAME);
  }

  @Override
  protected void doFilter(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
      throws IOException, ServletException {
    if (isAuthorized(req) || req.getRequestURI().equals(configuration.callbackPath())) {
      super.doFilter(req, res, chain);
      return;
    }
    if (Utils.isNavigation(req) && Utils.isSafeMethod(req)) {
      redirectToAuthenticationEndpoint(req, res);
      return;
    }
    sendUnauthorized(req, res);
  }

  protected abstract boolean isAuthorized(HttpServletRequest req);

  @ForOverride
  protected void redirectToAuthenticationEndpoint(HttpServletRequest req, HttpServletResponse res)
      throws IOException, ServletException {
    State state = new State();
    Nonce nonce = new Nonce();
    CodeVerifier codeVerifier = new CodeVerifier();
    req.getSession()
        .setAttribute(
            AuthenticationState.SESSION_ATTRIBUTE_NAME,
            new AuthenticationState(state, nonce, codeVerifier, requestUri(req)));
    AuthenticationRequest.Builder authenticationRequestBuilder =
        new AuthenticationRequest.Builder(
            ResponseType.CODE,
            new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.PROFILE, OIDCScopeValue.EMAIL),
            configuration.clientAuthentication().getClientID(),
            URI.create(req.getRequestURL().toString()).resolve(configuration.callbackPath()));
    authenticationRequestBuilder
        .endpointURI(configuration.providerMetadata().getAuthorizationEndpointURI())
        .state(state)
        .nonce(nonce)
        // From RFC: If the client is capable of using S256, it MUST use S256.
        .codeChallenge(codeVerifier, CodeChallengeMethod.S256);
    Utils.sendRedirect(res, authenticationRequestBuilder.build().toURI().toASCIIString());
  }

  private String requestUri(HttpServletRequest req) {
    return req.getQueryString() == null
        ? req.getRequestURI()
        : req.getRequestURI() + "?" + req.getQueryString();
  }

  @ForOverride
  protected void sendUnauthorized(HttpServletRequest req, HttpServletResponse res)
      throws IOException, ServletException {
    // XXX: this is not http-compliant as it's missing WWW-Authenticate
    res.sendError(HttpServletResponse.SC_UNAUTHORIZED);
  }
}
