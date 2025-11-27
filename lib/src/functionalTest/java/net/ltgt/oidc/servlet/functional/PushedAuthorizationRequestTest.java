package net.ltgt.oidc.servlet.functional;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth.assertWithMessage;
import static net.ltgt.oidc.servlet.fixtures.Helpers.login;
import static net.ltgt.oidc.servlet.fixtures.Helpers.logoutFromIdP;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.PushedAuthorizationRequest;
import com.nimbusds.oauth2.sdk.PushedAuthorizationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.util.function.Consumer;
import net.ltgt.oidc.servlet.AuthenticationRedirector;
import net.ltgt.oidc.servlet.IsAuthenticatedFilter;
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
                @Override
                protected void sendRedirect(
                    AuthenticationRequest authenticationRequest, Consumer<URI> sendRedirect) {
                  var request =
                      new PushedAuthorizationRequest(
                          configuration
                              .getProviderMetadata()
                              .getPushedAuthorizationRequestEndpointURI(),
                          configuration.getClientAuthenticationSupplier().getClientAuthentication(),
                          authenticationRequest);
                  PushedAuthorizationResponse response;
                  try {
                    response = PushedAuthorizationResponse.parse(request.toHTTPRequest().send());
                  } catch (ParseException e) {
                    throw new RuntimeException(e);
                  } catch (IOException e) {
                    throw new UncheckedIOException(e);
                  }
                  if (!response.indicatesSuccess()) {
                    throw new RuntimeException(
                        response.toErrorResponse().getErrorObject().toString());
                  }
                  sendRedirect.accept(
                      new AuthenticationRequest.Builder(
                              response.toSuccessResponse().getRequestURI(),
                              authenticationRequest.getClientID())
                          .endpointURI(authenticationRequest.getEndpointURI())
                          .build()
                          .toURI());
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
