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

  public AuthenticationRedirector(Configuration configuration, String callbackPath) {
    this.configuration = requireNonNull(configuration);
    this.callbackPath = requireNonNull(callbackPath);
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
   * <p>The target page should be given as an absolute path (possibly with a query string), though a
   * full URL would be accepted as long as it's the same <a
   * href="https://datatracker.ietf.org/doc/html/rfc6454">origin</a>. It will be saved in the
   * session to be redirected to from the {@link CallbackServlet}.
   */
  public void redirectToAuthenticationEndpoint(
      HttpServletRequest req,
      HttpServletResponse res,
      String returnTo,
      @Nullable Consumer<AuthenticationRequest.Builder> configureAuthenticationRequest) {
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
            configuration.getClientAuthentication().getClientID(),
            URI.create(req.getRequestURL().toString()).resolve(callbackPath));
    if (configureAuthenticationRequest != null) {
      configureAuthenticationRequest.accept(authenticationRequestBuilder);
    }
    configureAuthenticationRequest(authenticationRequestBuilder);
    authenticationRequestBuilder
        .endpointURI(configuration.getProviderMetadata().getAuthorizationEndpointURI())
        .state(state)
        .nonce(nonce)
        // From RFC: If the client is capable of using S256, it MUST use S256.
        .codeChallenge(codeVerifier, CodeChallengeMethod.S256);
    Utils.sendRedirect(res, authenticationRequestBuilder.build().toURI().toASCIIString());
  }

  /**
   * Called by {@link #redirectToAuthenticationEndpoint(HttpServletRequest, HttpServletResponse,
   * String, Consumer) redirectToAuthenticationEndpoint} to configure the authentication request
   * further.
   *
   * <p>The {@link Consumer configurator} passed to {@code redirectToAuthenticationEndpoint}, if
   * any, will be called before this method. Then {@code redirectToAuthenticationEndpoint} will
   * finalize configuration after this method (possibly overwriting some properties) before
   * redirecting.
   */
  @ForOverride
  protected void configureAuthenticationRequest(
      AuthenticationRequest.Builder authenticationRequestBuilder) {}
}
