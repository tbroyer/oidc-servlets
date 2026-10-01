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
import static net.ltgt.oidc.servlet.fixtures.Helpers.login;
import static net.ltgt.oidc.servlet.fixtures.Helpers.logoutFromIdP;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.dpop.DPoPProofFactory;
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;
import jakarta.servlet.http.HttpSession;
import net.ltgt.oidc.servlet.DPoPSupport;
import net.ltgt.oidc.servlet.IsAuthenticatedFilter;
import net.ltgt.oidc.servlet.OAuthTokensHandler;
import net.ltgt.oidc.servlet.SessionInfo;
import net.ltgt.oidc.servlet.SimpleUserPrincipal;
import net.ltgt.oidc.servlet.UserPrincipal;
import net.ltgt.oidc.servlet.UserPrincipalFactory;
import net.ltgt.oidc.servlet.fixtures.WebDriverExtension;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.openqa.selenium.WebDriver;

public class ExtensibilityErrorHandlerTest {

  @Nested
  @ExtendWith(WebDriverExtension.class)
  public class ErroringUserPrincipalFactory {
    @RegisterExtension
    public WebServerExtension server =
        new WebServerExtension(
            "simple",
            contextHandler -> {
              contextHandler.addFilter(IsAuthenticatedFilter.class, "/*", null);

              contextHandler.setAttribute(
                  UserPrincipalFactory.CONTEXT_ATTRIBUTE_NAME,
                  new UserPrincipalFactory() {
                    @Override
                    public UserPrincipal createUserPrincipal(
                        SessionInfo sessionInfo, HttpSession session) {
                      return new SimpleUserPrincipal(sessionInfo);
                    }

                    @Override
                    public void userAuthenticated(SessionInfo sessionInfo, HttpSession session) {
                      throw new RuntimeException("UserPrincipalFactory.userAuthenticated");
                    }
                  });
            });

    private final WebDriver driver;

    public ErroringUserPrincipalFactory(WebDriver driver) {
      this.driver = driver;
    }

    @AfterEach
    public void logout() {
      logoutFromIdP(driver, server);
    }

    @Test
    public void test() throws Exception {
      driver.get(server.getURI("/"));

      login(driver, server, "user", "user");

      assertWithMessage("Should error out")
          .that(driver.getCurrentUrl())
          .startsWith(server.getURI(WebServerExtension.CALLBACK_PATH));
      assertThat(driver.getTitle()).contains("Error finalizing authentication");

      driver.get(server.getURI("/"));
      assertWithMessage("Shouldn't have been authenticated")
          .that(driver.getCurrentUrl())
          .startsWith(server.getURI(WebServerExtension.CALLBACK_PATH));
      assertThat(driver.getTitle()).contains("Error finalizing authentication");
    }
  }

  @Nested
  @ExtendWith(WebDriverExtension.class)
  public class ErroringOAuthTokensHandler {
    @RegisterExtension
    public WebServerExtension server =
        new WebServerExtension(
            "simple",
            contextHandler -> {
              contextHandler.addFilter(IsAuthenticatedFilter.class, "/*", null);

              contextHandler.setAttribute(
                  OAuthTokensHandler.CONTEXT_ATTRIBUTE_NAME,
                  new OAuthTokensHandler() {
                    @Override
                    public void tokensAcquired(
                        AccessTokenResponse tokenResponse, HttpSession session) {
                      throw new RuntimeException("OAuthTokensHandler.tokensAcquired");
                    }
                  });
            });

    private final WebDriver driver;

    public ErroringOAuthTokensHandler(WebDriver driver) {
      this.driver = driver;
    }

    @AfterEach
    public void logout() {
      logoutFromIdP(driver, server);
    }

    @Test
    public void test() throws Exception {
      driver.get(server.getURI("/"));

      login(driver, server, "user", "user");

      assertWithMessage("Should error out")
          .that(driver.getCurrentUrl())
          .startsWith(server.getURI(WebServerExtension.CALLBACK_PATH));
      assertThat(driver.getTitle()).contains("Error finalizing authentication");

      driver.get(server.getURI("/"));
      assertWithMessage("Shouldn't have been authenticated")
          .that(driver.getCurrentUrl())
          .startsWith(server.getURI(WebServerExtension.CALLBACK_PATH));
      assertThat(driver.getTitle()).contains("Error finalizing authentication");
    }
  }

  @Nested
  @ExtendWith(WebDriverExtension.class)
  public class ErroringDPoPSupport {
    @RegisterExtension
    public WebServerExtension server =
        new WebServerExtension(
            "simple",
            contextHandler -> {
              contextHandler.addFilter(IsAuthenticatedFilter.class, "/*", null);

              contextHandler.setAttribute(
                  DPoPSupport.CONTEXT_ATTRIBUTE_NAME,
                  new DPoPSupport() {
                    @Override
                    public DPoPProofFactory getProofFactory(HttpSession session) {
                      throw new RuntimeException("DPoPSupport.getProofFactory");
                    }

                    @Override
                    public JWKThumbprintConfirmation getJWKThumbprintConfirmation(
                        HttpSession session) {
                      try {
                        return DPoPSupport.create(
                                new ECKeyGenerator(Curve.P_256).generate(), JWSAlgorithm.ES256)
                            .getJWKThumbprintConfirmation(session);
                      } catch (JOSEException e) {
                        throw new RuntimeException(e);
                      }
                    }
                  });
            });

    private final WebDriver driver;

    public ErroringDPoPSupport(WebDriver driver) {
      this.driver = driver;
    }

    @AfterEach
    public void logout() {
      logoutFromIdP(driver, server);
    }

    @Test
    public void test() throws Exception {
      driver.get(server.getURI("/"));

      login(driver, server, "user", "user");

      assertWithMessage("Should error out")
          .that(driver.getCurrentUrl())
          .startsWith(server.getURI(WebServerExtension.CALLBACK_PATH));
      assertThat(driver.getTitle()).contains("Error in token request");

      driver.get(server.getURI("/"));
      assertWithMessage("Shouldn't have been authenticated")
          .that(driver.getCurrentUrl())
          .startsWith(server.getURI(WebServerExtension.CALLBACK_PATH));
      assertThat(driver.getTitle()).contains("Error in token request");
    }
  }
}
