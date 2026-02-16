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

import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import java.net.URI;
import java.util.function.Consumer;
import net.ltgt.oidc.servlet.AuthenticationRedirector;
import net.ltgt.oidc.servlet.IsAuthenticatedFilter;
import net.ltgt.oidc.servlet.PushedAuthorizationRequestHelper;
import net.ltgt.oidc.servlet.fixtures.WebDriverExtension;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.openqa.selenium.WebDriver;

@ExtendWith(WebDriverExtension.class)
public class PushedAuthorizationRequestTest {
  @RegisterExtension
  public WebServerExtension server =
      new WebServerExtension(
          "simple",
          (configuration, callbackPath) ->
              new AuthenticationRedirector(configuration, callbackPath) {
                private final PushedAuthorizationRequestHelper pushedAuthorizationRequestHelper =
                    new PushedAuthorizationRequestHelper(configuration);

                @Override
                protected void sendRedirect(
                    AuthenticationRequest authenticationRequest, Consumer<URI> sendRedirect) {
                  pushedAuthorizationRequestHelper.sendRedirect(
                      authenticationRequest, sendRedirect);
                }
              },
          contextHandler -> {
            contextHandler.addFilter(IsAuthenticatedFilter.class, "/*", null);
          });

  private final WebDriver driver;

  public PushedAuthorizationRequestTest(WebDriver driver) {
    this.driver = driver;
  }

  @AfterEach
  public void logout() {
    logoutFromIdP(driver, server);
  }

  @Test
  public void test() {
    driver.get(server.getURI("/"));

    login(driver, server, "user", "user");

    assertWithMessage("Should redirect back to application, authenticated")
        .that(driver.getCurrentUrl())
        .isEqualTo(server.getURI("/"));
    assertThat(driver.getTitle()).isEqualTo("Test page");
  }
}
