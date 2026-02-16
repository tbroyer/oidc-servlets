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
import static com.google.common.truth.TruthJUnit.assume;
import static java.util.Objects.requireNonNull;
import static net.ltgt.oidc.servlet.fixtures.Helpers.login;
import static net.ltgt.oidc.servlet.fixtures.Helpers.logoutFromIdP;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import jakarta.servlet.http.HttpSession;
import net.ltgt.oidc.servlet.AuthenticationRedirector;
import net.ltgt.oidc.servlet.Configuration;
import net.ltgt.oidc.servlet.DPoPSupport;
import net.ltgt.oidc.servlet.IsAuthenticatedFilter;
import net.ltgt.oidc.servlet.OAuthTokensHandler;
import net.ltgt.oidc.servlet.RevokingOAuthTokensHandler;
import net.ltgt.oidc.servlet.fixtures.WebDriverExtension;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.openqa.selenium.WebDriver;

@ExtendWith(WebDriverExtension.class)
public class DPoPTest {
  final DPoPSupport dpopSupport;

  {
    try {
      dpopSupport =
          DPoPSupport.create(new ECKeyGenerator(Curve.P_256).generate(), JWSAlgorithm.ES256);
    } catch (JOSEException e) {
      throw new RuntimeException(e);
    }
  }

  @RegisterExtension
  public WebServerExtension server =
      new WebServerExtension(
          "simple",
          (configuration, callbackPath) ->
              new AuthenticationRedirector(configuration, callbackPath, dpopSupport),
          contextHandler -> {
            contextHandler.setAttribute(DPoPSupport.CONTEXT_ATTRIBUTE_NAME, dpopSupport);
            contextHandler.setAttribute(
                OAuthTokensHandler.CONTEXT_ATTRIBUTE_NAME,
                new RevokingOAuthTokensHandler(
                    (Configuration)
                        requireNonNull(
                            contextHandler.getAttribute(Configuration.CONTEXT_ATTRIBUTE_NAME))) {
                  @Override
                  public void tokensAcquired(
                      AccessTokenResponse tokenResponse, HttpSession session) {
                    assertThat(tokenResponse.getTokens().getDPoPAccessToken()).isNotNull();
                    super.tokensAcquired(tokenResponse, session);
                  }
                });
            contextHandler.addFilter(IsAuthenticatedFilter.class, "/*", null);
          });

  private final WebDriver driver;

  public DPoPTest(WebDriver driver) {
    this.driver = driver;
  }

  @AfterEach
  public void logout() {
    logoutFromIdP(driver, server);
  }

  @Test
  public void test() {
    assume().that(server.getProviderMetadata().getDPoPJWSAlgs()).contains(JWSAlgorithm.ES256);

    driver.get(server.getURI("/"));

    login(driver, server, "user", "user");

    assertWithMessage("Should redirect back to application, authenticated")
        .that(driver.getCurrentUrl())
        .isEqualTo(server.getURI("/"));
    assertThat(driver.getTitle()).isEqualTo("Test page");
  }
}
