package net.ltgt.oidc.servlet;

import static java.util.Objects.requireNonNull;

import com.google.errorprone.annotations.ForOverride;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.TokenRevocationRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequestSender;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.Token;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.concurrent.Executor;
import java.util.concurrent.ForkJoinPool;
import org.jspecify.annotations.Nullable;

/**
 * An {@link OAuthTokensHandler} that immediately (though asynchronously) revokes the access token.
 *
 * <p>This is the default handler used by the {@link CallbackServlet} when no specific handler has
 * been configured, using the {@linkplain Utils#HTTP_REQUEST_SENDER_CONTEXT_ATTRIBUTE_NAME globally
 * configured} HTTP request sender.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7009">OAuth 2.0 Token Revocation</a>
 */
public class RevokingOAuthTokensHandler implements OAuthTokensHandler {
  private final Configuration configuration;
  private final @Nullable HTTPRequestSender httpRequestSender;
  private final Executor executor;

  /**
   * Constructs a revoking token handler with the given configuration.
   *
   * <p>The asynchronous task will be executed in the {@link ForkJoinPool#commonPool()}.
   */
  public RevokingOAuthTokensHandler(Configuration configuration) {
    this(configuration, (HTTPRequestSender) null);
  }

  /**
   * Constructs a revoking token handler with the given configuration and HTTP request sender.
   *
   * <p>The asynchronous task will be executed in the {@link ForkJoinPool#commonPool()}.
   */
  public RevokingOAuthTokensHandler(
      Configuration configuration, @Nullable HTTPRequestSender httpRequestSender) {
    this(configuration, httpRequestSender, ForkJoinPool.commonPool());
  }

  /**
   * Constructs a revoking token handler with the given configuration and executor, and no HTTP
   * executor sender.
   */
  public RevokingOAuthTokensHandler(Configuration configuration, Executor executor) {
    this(configuration, null, executor);
  }

  /**
   * Constructs a revoking token handler with the given configuration, HTTP executor sender, and
   * executor.
   */
  public RevokingOAuthTokensHandler(
      Configuration configuration,
      @Nullable HTTPRequestSender httpRequestSender,
      Executor executor) {
    this.configuration = requireNonNull(configuration);
    this.httpRequestSender = httpRequestSender;
    this.executor = requireNonNull(executor);
  }

  @Override
  public void tokensAcquired(AccessTokenResponse tokenResponse, HttpSession session) {
    revokeAsync(tokenResponse.getTokens().getAccessToken());
  }

  void revokeAsync(Token token) {
    executor.execute(
        () -> {
          try {
            revoke(token);
          } catch (IOException e) {
            handleError(e);
          }
        });
  }

  private void revoke(Token token) throws IOException {
    var request =
        new TokenRevocationRequest(
            configuration.getProviderMetadata().getRevocationEndpointURI(),
            configuration.getClientAuthenticationSupplier().getClientAuthentication(),
            token);
    var response = send(request);
    if (!response.indicatesSuccess()) {
      handleError(response);
    }
  }

  private HTTPResponse send(TokenRevocationRequest request) throws IOException {
    if (httpRequestSender != null) {
      return request.toHTTPRequest().send(httpRequestSender);
    } else {
      return request.toHTTPRequest().send();
    }
  }

  /**
   * Handles an exception happening in the asynchronous revocation task.
   *
   * @implSpec The default implementation re-throws the exception, possibly wrapped in an {@link
   *     UncheckedIOException} or a {@link RuntimeException}.
   */
  @ForOverride
  protected void handleError(Exception e) {
    switch (e) {
      case RuntimeException re -> throw re;
      case IOException ioe -> throw new UncheckedIOException(ioe);
      default -> throw new RuntimeException(e);
    }
  }

  /**
   * Handles an unsuccessful response to the token revocation request.
   *
   * @implSpec The default implementation does nothing.
   */
  @ForOverride
  protected void handleError(HTTPResponse response) {}
}
