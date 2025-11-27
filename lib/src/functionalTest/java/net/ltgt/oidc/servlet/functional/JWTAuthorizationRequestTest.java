package net.ltgt.oidc.servlet.functional;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth.assertWithMessage;
import static com.google.common.truth.TruthJUnit.assume;
import static net.ltgt.oidc.servlet.fixtures.Helpers.login;
import static net.ltgt.oidc.servlet.fixtures.Helpers.logoutFromIdP;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.auth.PlainClientSecret;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
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
public class JWTAuthorizationRequestTest {
  @RegisterExtension
  public WebServerExtension server =
      new WebServerExtension(
          "simple",
          (configuration, callbackPath) ->
              new AuthenticationRedirector(configuration, callbackPath) {
                @Override
                protected void sendRedirect(
                    AuthenticationRequest authenticationRequest, Consumer<URI> sendRedirect) {
                  var jar =
                      new SignedJWT(
                          new JWSHeader.Builder(JWSAlgorithm.HS256).build(),
                          authenticationRequest.toJWTClaimsSet());
                  try {
                    jar.sign(
                        new MACSigner(
                            ((PlainClientSecret)
                                    configuration
                                        .getClientAuthenticationSupplier()
                                        .getClientAuthentication())
                                .getClientSecret()
                                .getValueBytes()));
                  } catch (JOSEException e) {
                    throw new RuntimeException(e);
                  }
                  sendRedirect.accept(
                      new AuthenticationRequest.Builder(jar, authenticationRequest.getClientID())
                          .endpointURI(authenticationRequest.getEndpointURI())
                          .build()
                          .toURI());
                }
              },
          contextHandler -> {
            contextHandler.addFilter(IsAuthenticatedFilter.class, "/*", null);
          });

  private final WebDriver driver;

  public JWTAuthorizationRequestTest(WebDriver driver) {
    this.driver = driver;
  }

  @AfterEach
  public void logout() {
    logoutFromIdP(driver, server);
  }

  @Test
  public void test() {
    assume()
        .that(server.getProviderMetadata().getRequestObjectJWSAlgs())
        .contains(JWSAlgorithm.HS256);

    driver.get(server.getURI("/"));

    login(driver, server, "user", "user");

    assertWithMessage("Should redirect back to application, authenticated")
        .that(driver.getCurrentUrl())
        .isEqualTo(server.getURI("/"));
    assertThat(driver.getTitle()).isEqualTo("Test page");
  }
}
