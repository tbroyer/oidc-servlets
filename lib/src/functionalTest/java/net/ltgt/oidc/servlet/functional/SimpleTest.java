package net.ltgt.oidc.servlet.functional;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth.assertWithMessage;
import static net.ltgt.oidc.servlet.fixtures.Helpers.login;
import static org.openqa.selenium.support.ui.ExpectedConditions.stalenessOf;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import jakarta.servlet.http.HttpSession;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import net.ltgt.oidc.servlet.AuthenticationRedirector;
import net.ltgt.oidc.servlet.Configuration;
import net.ltgt.oidc.servlet.IsAuthenticatedFilter;
import net.ltgt.oidc.servlet.LogoutServlet;
import net.ltgt.oidc.servlet.OAuthTokensHandler;
import net.ltgt.oidc.servlet.RevokingOAuthTokensHandler;
import net.ltgt.oidc.servlet.fixtures.WebDriverExtension;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.ui.WebDriverWait;

@ParameterizedClass
@NullSource
@ValueSource(strings = {"form_post"})
@ExtendWith(WebDriverExtension.class)
public class SimpleTest {
  ExecutorService revocationExecutor = Executors.newCachedThreadPool();
  List<AccessToken> accessTokens = new CopyOnWriteArrayList<>();

  @RegisterExtension public WebServerExtension server;

  SimpleTest(@Nullable ResponseMode responseMode) {
    server =
        new WebServerExtension(
            "simple",
            responseMode == null
                ? AuthenticationRedirector::new
                : (configuration, callbackPath) ->
                    new AuthenticationRedirector(configuration, callbackPath) {
                      @Override
                      protected void configureAuthenticationRequest(
                          AuthenticationRequest.Builder authenticationRequestBuilder) {
                        // Note: form_post only works because we use Chrome
                        // https://www.chromium.org/updates/same-site/faq/#q-what-is-the-lax-post-mitigation
                        // This can break anytime as Chrome eventually removes Lax+POST.
                        authenticationRequestBuilder.responseMode(responseMode);
                      }
                    },
            contextHandler -> {
              contextHandler.addFilter(IsAuthenticatedFilter.class, "/*", null);
              contextHandler.addServlet(LogoutServlet.class, "/logout");

              contextHandler.setAttribute(
                  OAuthTokensHandler.CONTEXT_ATTRIBUTE_NAME,
                  new RevokingOAuthTokensHandler(
                      (Configuration)
                          contextHandler.getAttribute(Configuration.CONTEXT_ATTRIBUTE_NAME),
                      revocationExecutor) {
                    @Override
                    public void tokensAcquired(
                        AccessTokenResponse tokenResponse, HttpSession session) {
                      accessTokens.add(tokenResponse.getTokens().getAccessToken());
                      super.tokensAcquired(tokenResponse, session);
                    }
                  });
            });
  }

  @Test
  public void loginThenLogout(WebDriver driver) throws Exception {
    driver.get(server.getURI("/"));

    login(driver, server, "user", "user");

    assertWithMessage("Should redirect back to application, authenticated")
        .that(driver.getCurrentUrl())
        .isEqualTo(server.getURI("/"));
    assertThat(driver.getTitle()).isEqualTo("Test page");

    // Wait for revocation requests to terminate
    revocationExecutor.shutdown();
    assertThat(revocationExecutor.awaitTermination(5, TimeUnit.MINUTES)).isTrue();

    for (AccessToken accessToken : this.accessTokens) {
      checkAccessTokenInactive(accessToken);
    }

    var logout = driver.findElement(By.id("logout"));
    logout.click();
    new WebDriverWait(driver, Duration.ofSeconds(2)).until(stalenessOf(logout));
    assertWithMessage("Should redirect to IdP for logout")
        .that(driver.getCurrentUrl())
        .startsWith(server.getIssuer());
    assertThat(driver.findElement(By.id("kc-page-title")).getText()).contains("You are logged out");
  }

  private void checkAccessTokenInactive(AccessToken accessToken) throws Exception {
    var userInfoRequest =
        new UserInfoRequest(server.getProviderMetadata().getUserInfoEndpointURI(), accessToken);
    var userInfoResponse = UserInfoResponse.parse(userInfoRequest.toHTTPRequest().send());
    assertThat(userInfoResponse.indicatesSuccess()).isFalse();
  }
}
