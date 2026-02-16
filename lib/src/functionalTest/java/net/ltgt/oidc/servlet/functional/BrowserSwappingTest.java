/*
 * Copyright © 2026 Thomas Broyer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.ltgt.oidc.servlet.functional;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth.assertWithMessage;
import static java.util.Objects.requireNonNull;
import static net.ltgt.oidc.servlet.fixtures.Helpers.login;
import static net.ltgt.oidc.servlet.fixtures.Helpers.logoutFromIdP;
import static net.ltgt.oidc.servlet.fixtures.WebServerExtension.CALLBACK_PATH;
import static org.openqa.selenium.support.ui.ExpectedConditions.urlMatches;

import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import net.ltgt.oidc.servlet.AuthenticationRedirector;
import net.ltgt.oidc.servlet.CallbackServlet;
import net.ltgt.oidc.servlet.IsAuthenticatedFilter;
import net.ltgt.oidc.servlet.fixtures.WebDriverExtension;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.ui.WebDriverWait;

public class BrowserSwappingTest {
  /**
   * Test some protection against browser-swapping attack.
   *
   * @see <a
   *     href="https://mailarchive.ietf.org/arch/msg/oauth/K8Wnw08GzPstyAQAh0JmSB47pOQ/">discussion
   *     in IETF OAuth WG</a>
   * @see <a
   *     href="https://datatracker.ietf.org/meeting/124/materials/slides-124-oauth-sessa-browser-swapping-01">slides
   *     from IETF 124</a>
   * @see <a
   *     href="https://openid.net/specs/fapi-security-profile-2_0-final.html#name-browser-swapping-attacks">Browser-swapping
   *     attacks section in OpenID Connect FAPI 2.0 Security Profile</a>
   */
  @Nested
  @ExtendWith(WebDriverExtension.class)
  public class WithQueryResponseForm {
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
                  protected void sendRedirect(
                      AuthenticationRequest authenticationRequest, Consumer<URI> sendRedirect) {
                    var uri = authenticationRequest.toURI();
                    authenticationEndpointRedirects.add(uri.toString());
                    sendRedirect.accept(uri);
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

    private final WebDriver victimDriver;

    public WithQueryResponseForm(WebDriver victimDriver) {
      this.victimDriver = victimDriver;
    }

    @AfterEach
    public void logout() {
      logoutFromIdP(victimDriver, server);
    }

    @Test
    void test(WebDriver attackerDriver) {
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

  /**
   * Test some protection against browser-swapping attack.
   *
   * @see <a
   *     href="https://mailarchive.ietf.org/arch/msg/oauth/TskANcfNy7NNir-hbmcmFASDVog/">discussion
   *     in IETF OAuth WG</a>
   * @see <a
   *     href="https://medium.com/@anador/attacks-via-a-new-oauth-flow-authorization-code-injection-and-whether-httponly-pkce-and-bff-3db1624b4fa7">Attacks
   *     via a New OAuth flow, Authorization Code Injection, and Whether HttpOnly, PKCE, and BFF Can
   *     Help</a>
   */
  @Nested
  @ExtendWith(WebDriverExtension.class)
  public class WithFragmentResponseForm {
    private final List<String> authenticationEndpointRedirects = new ArrayList<>();

    @RegisterExtension
    public WebServerExtension server =
        new WebServerExtension(
            "simple",
            // The attacker would extract the URL from its browser directly
            // This approach is simpler in test code with webdriver though
            (configuration, callbackPath) ->
                new AuthenticationRedirector(configuration, callbackPath) {
                  @Override
                  protected void sendRedirect(
                      AuthenticationRequest authenticationRequest, Consumer<URI> sendRedirect) {
                    var uri = authenticationRequest.toURI();
                    authenticationEndpointRedirects.add(uri.toString());
                    sendRedirect.accept(uri);
                  }
                },
            contextHandler -> {
              contextHandler.addFilter(IsAuthenticatedFilter.class, "/*", null);
            });

    private final WebDriver victimDriver;

    public WithFragmentResponseForm(WebDriver victimDriver) {
      this.victimDriver = victimDriver;
    }

    @AfterEach
    public void logout() {
      logoutFromIdP(victimDriver, server);
    }

    @Test
    void test(WebDriver attackerDriver) {
      // Attacker:
      attackerDriver.get(server.getURI("/"));
      new WebDriverWait(attackerDriver, Duration.ofSeconds(2))
          .withMessage("Should redirect to IdP")
          .until(urlMatches("^\\Q" + server.getIssuer()));
      assertThat(authenticationEndpointRedirects).isNotEmpty();

      // Victim:
      victimDriver.get(authenticationEndpointRedirects.removeFirst() + "&response_mode=fragment");
      login(victimDriver, server, "user", "user");
      assertWithMessage("Should redirect back to application")
          .that(victimDriver.getCurrentUrl())
          .startsWith(server.getURI("/"));
      assertWithMessage("Should not leave an authorization code in the URL")
          .that(victimDriver.getCurrentUrl())
          .doesNotContainMatch("\\bcode=");
      assertThat(victimDriver.getTitle()).contains(CallbackServlet.ERROR_PARSING_PARAMETERS);

      // Attacker:
      attackerDriver.get(requireNonNull(victimDriver.getCurrentUrl()).replace('#', '?'));
      assertWithMessage("Should not redirect back to application, authenticated")
          .that(attackerDriver.getCurrentUrl())
          .isNotEqualTo(server.getURI("/"));
      assertThat(attackerDriver.getTitle()).contains(CallbackServlet.ERROR_PARSING_PARAMETERS);
    }
  }
}
