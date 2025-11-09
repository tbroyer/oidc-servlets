package net.ltgt.oidc.servlet.functional;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth.assertWithMessage;
import static net.ltgt.oidc.servlet.fixtures.Helpers.login;
import static net.ltgt.oidc.servlet.fixtures.WebServerExtension.CALLBACK_PATH;
import static org.openqa.selenium.support.ui.ExpectedConditions.urlMatches;

import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import jakarta.servlet.http.HttpSession;
import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import net.ltgt.oidc.servlet.AuthenticationRedirector;
import net.ltgt.oidc.servlet.IsAuthenticatedFilter;
import net.ltgt.oidc.servlet.fixtures.WebDriverExtension;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.ui.WebDriverWait;

/**
 * Test some protection against browser-swapping attack.
 *
 * @see <a
 *     href="https://mailarchive.ietf.org/arch/msg/oauth/K8Wnw08GzPstyAQAh0JmSB47pOQ/">discussion in
 *     IETF OAuth WG</a>
 * @see <a
 *     href="https://datatracker.ietf.org/meeting/124/materials/slides-124-oauth-sessa-browser-swapping-01">slides
 *     from IETF 124</a>
 * @see <a
 *     href="https://openid.net/specs/fapi-security-profile-2_0-final.html#name-browser-swapping-attacks">Browser-swapping
 *     attacks section in OpenID Connect FAPI 2.0 Security Profile</a>
 */
@ExtendWith(WebDriverExtension.class)
public class BrowserSwappingTest {
  private final List<String> authenticationEndpointRedirects = new ArrayList<>();
  private final List<String> callbackRequestUris = new ArrayList<>();

  @RegisterExtension
  public WebServerExtension server =
      new WebServerExtension(
          "simple",
          // The attacker would extract the URL from its browser directly
          // This approach is simpler in test code with webdriver though
          (configuration, callbackPath) ->
              new AuthenticationRedirector(configuration, callbackPath) {
                @Override
                protected void redirectToAuthenticationEndpoint(
                    HttpSession session,
                    String returnTo,
                    @Nullable Consumer<AuthenticationRequest.Builder>
                        configureAuthenticationRequest,
                    URI baseUri,
                    Consumer<URI> sendRedirect) {
                  super.redirectToAuthenticationEndpoint(
                      session,
                      returnTo,
                      configureAuthenticationRequest,
                      baseUri,
                      uri -> {
                        authenticationEndpointRedirects.add(uri.toString());
                        sendRedirect.accept(uri);
                      });
                }
              },
          contextHandler -> {
            // Mimic access by the attacker to access logs in near real-time
            contextHandler
                .getServer()
                .setRequestLog(
                    (request, response) -> {
                      if (request.getHttpURI().getPath().equals(CALLBACK_PATH)) {
                        callbackRequestUris.add(request.getHttpURI().asString());
                      }
                    });

            contextHandler.addFilter(IsAuthenticatedFilter.class, "/*", null);
          });

  @Test
  void test(WebDriver attackerDriver, WebDriver victimDriver) {
    // Attacker:
    attackerDriver.get(server.getURI("/"));
    new WebDriverWait(attackerDriver, Duration.ofSeconds(2))
        .withMessage("Should redirect to IdP")
        .until(urlMatches("^\\Q" + server.getIssuer()));
    assertThat(authenticationEndpointRedirects).isNotEmpty();
    assertThat(callbackRequestUris).isEmpty();

    // Victim:
    victimDriver.get(authenticationEndpointRedirects.removeFirst());
    login(victimDriver, server, "user", "user");
    assertWithMessage("Should redirect back to application, failing auth")
        .that(victimDriver.getCurrentUrl())
        .isNotEqualTo(server.getURI("/"));
    assertThat(victimDriver.getTitle())
        .contains("Missing saved state from authorization request initiation");
    assertThat(callbackRequestUris).isNotEmpty();

    // Attacker:
    attackerDriver.get(callbackRequestUris.removeFirst());
    assertWithMessage("Should not redirect back to application, authenticated")
        .that(attackerDriver.getCurrentUrl())
        .isNotEqualTo(server.getURI("/"));
    assertThat(attackerDriver.getTitle()).contains("Token request returned error: invalid_grant");
  }
}
