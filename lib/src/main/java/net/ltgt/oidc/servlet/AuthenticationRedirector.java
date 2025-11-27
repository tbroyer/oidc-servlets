package net.ltgt.oidc.servlet;

import static java.util.Objects.requireNonNull;

import com.google.errorprone.annotations.ForOverride;
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
import jakarta.servlet.http.HttpSession;
import java.net.URI;
import java.util.function.Consumer;
import org.jspecify.annotations.Nullable;

/**
 * Responsible for redirecting to the OpenID Provider.
 *
 * <p>An instance of this class needs to be added as a {@link jakarta.servlet.ServletContext
 * ServletContext} attribute under the name {@link #CONTEXT_ATTRIBUTE_NAME}, to be used by the
 * {@linkplain AbstractAuthorizationFilter authorization filters} or the {@link LoginServlet}.
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect Core 1.0</a>
 * @see AbstractAuthorizationFilter
 * @see IsAuthenticatedFilter
 * @see HasRoleFilter
 * @see LoginServlet
 */
public class AuthenticationRedirector {
  public static final String CONTEXT_ATTRIBUTE_NAME = AuthenticationRedirector.class.getName();

  private final Configuration configuration;
  private final String callbackPath;
  private final @Nullable DPoPSupport dpopSupport;

  public AuthenticationRedirector(Configuration configuration, String callbackPath) {
    this(configuration, callbackPath, null);
  }

  public AuthenticationRedirector(
      Configuration configuration, String callbackPath, @Nullable DPoPSupport dpopSupport) {
    this.configuration = requireNonNull(configuration);
    this.callbackPath = requireNonNull(callbackPath);
    this.dpopSupport = dpopSupport;
  }

  /**
   * Redirects to the OpenID Provider, returning to the given page when coming back.
   *
   * <p>This is equivalent to {@code redirectToAuthenticationEndpoint(req, res, returnTo, null)}.
   */
  public void redirectToAuthenticationEndpoint(
      HttpServletRequest req, HttpServletResponse res, String returnTo) {
    redirectToAuthenticationEndpoint(req, res, returnTo, null);
  }

  /**
   * Redirects to the OpenID Provider, returning to the given page when coming back, and possibly
   * configuring the authentication request further.
   *
   * <p>This is equivalent to {@code redirectToAuthenticationEndpoint(req.getSession(), returnTo,
   * configureAuthenticationRequest, URI.create(req.getRequestURL().toString()), uri ->
   * Utils.sendRedirect(res, uri.toASCIIString()))}.
   */
  public void redirectToAuthenticationEndpoint(
      HttpServletRequest req,
      HttpServletResponse res,
      String returnTo,
      @Nullable Consumer<AuthenticationRequest.Builder> configureAuthenticationRequest) {
    redirectToAuthenticationEndpoint(
        req.getSession(),
        returnTo,
        configureAuthenticationRequest,
        URI.create(req.getRequestURL().toString()),
        uri -> Utils.sendRedirect(res, uri.toASCIIString()));
  }

  /**
   * Redirects to the OpenID Provider, returning to the given page when coming back, and possibly
   * configuring the authentication request further.
   *
   * <p>The target page should be given as an absolute path (possibly with a query string), though a
   * full URL would be accepted as long as it's the same <a
   * href="https://datatracker.ietf.org/doc/html/rfc6454">origin</a>. It will be saved in the
   * session to be redirected to from the {@link CallbackServlet}.
   *
   * <p>The base URI is used to resolve the {@code callbackPath} passed to the constructor, to build
   * the authentication request's {@code redirect_uri}. The {@code sendRedirect} is the actual
   * implementation of the redirect response, depending on the environment (specifically using
   * JAX-RS in the OIDC-Servlets+RS library).
   */
  public void redirectToAuthenticationEndpoint(
      HttpSession session,
      String returnTo,
      @Nullable Consumer<AuthenticationRequest.Builder> configureAuthenticationRequest,
      URI baseUri,
      Consumer<URI> sendRedirect) {
    var state = new State();
    var nonce = new Nonce();
    var codeVerifier = new CodeVerifier();
    var dpopJkt = dpopSupport == null ? null : dpopSupport.getJWKThumbprintConfirmation(session);
    session.setAttribute(
        AuthenticationState.SESSION_ATTRIBUTE_NAME,
        new AuthenticationState(state, nonce, codeVerifier, returnTo));
    AuthenticationRequest.Builder authenticationRequestBuilder =
        new AuthenticationRequest.Builder(
            ResponseType.CODE,
            new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.PROFILE, OIDCScopeValue.EMAIL),
            configuration.getClientId(),
            baseUri.resolve(callbackPath));
    if (configureAuthenticationRequest != null) {
      configureAuthenticationRequest.accept(authenticationRequestBuilder);
    }
    configureAuthenticationRequest(authenticationRequestBuilder);
    authenticationRequestBuilder
        .endpointURI(configuration.getProviderMetadata().getAuthorizationEndpointURI())
        .state(state)
        .nonce(nonce)
        // From RFC: If the client is capable of using S256, it MUST use S256.
        .codeChallenge(codeVerifier, CodeChallengeMethod.S256)
        .dPoPJWKThumbprintConfirmation(dpopJkt);
    sendRedirect(authenticationRequestBuilder.build(), sendRedirect);
  }

  /**
   * Called by {@link #redirectToAuthenticationEndpoint(HttpServletRequest, HttpServletResponse,
   * String, Consumer) redirectToAuthenticationEndpoint} to configure the authentication request
   * further.
   *
   * <p>The {@link Consumer configurator} passed to {@code redirectToAuthenticationEndpoint}, if
   * any, will have been called before this method. Then {@code redirectToAuthenticationEndpoint}
   * will finalize configuration after this method (possibly overwriting some properties) before
   * redirecting.
   */
  @ForOverride
  protected void configureAuthenticationRequest(
      AuthenticationRequest.Builder authenticationRequestBuilder) {}

  /**
   * Called by {@link #redirectToAuthenticationEndpoint(HttpServletRequest, HttpServletResponse,
   * String, Consumer) redirectToAuthenticationEndpoint} to actually send the redirect.
   *
   * @implSpec The default implementation.simply calls {@code
   *     sendRedirect.accept(authenticationRequest.toURI())}.
   */
  @ForOverride
  protected void sendRedirect(
      AuthenticationRequest authenticationRequest, Consumer<URI> sendRedirect) {
    sendRedirect.accept(authenticationRequest.toURI());
  }
}
