package net.ltgt.oidc.servlet.rs.functional;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth.assertWithMessage;
import static net.ltgt.oidc.servlet.fixtures.Helpers.login;
import static net.ltgt.oidc.servlet.fixtures.Helpers.logoutFromIdP;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Application;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.SecurityContext;
import java.util.Set;
import net.ltgt.oidc.servlet.fixtures.WebDriverExtension;
import net.ltgt.oidc.servlet.rs.IsAuthenticated;
import net.ltgt.oidc.servlet.rs.IsAuthenticatedFilter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.openqa.selenium.WebDriver;

@ExtendWith(WebDriverExtension.class)
public class IsAuthenticatedTest {
  public static class TestApplication extends Application {
    @Override
    public Set<Class<?>> getClasses() {
      return Set.of(IsAuthenticatedFilter.class, TestResource.class);
    }
  }

  @Path("/")
  @IsAuthenticated
  public static class TestResource {
    @GET
    @Produces(MediaType.TEXT_HTML)
    public String get(@Context SecurityContext securityContext) {
      return """
          <!DOCTYPE html>
          <html lang="en">
          <head>
              <meta charset="UTF-8">
              <title>Test page</title>
          </head>
          <body>
              <h1>Test page</h1>
          </body>
          </html>
          """;
    }
  }

  @RegisterExtension
  public WebServerExtension server = new WebServerExtension(TestApplication.class);

  private final WebDriver driver;

  public IsAuthenticatedTest(WebDriver driver) {
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

    assertWithMessage("Should redirect back to application, authenticated")
        .that(driver.getCurrentUrl())
        .isEqualTo(server.getURI("/"));
    assertThat(driver.getTitle()).isEqualTo("Test page");
  }
}
