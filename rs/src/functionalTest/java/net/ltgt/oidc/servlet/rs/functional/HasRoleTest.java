package net.ltgt.oidc.servlet.rs.functional;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth.assertWithMessage;
import static net.ltgt.oidc.servlet.fixtures.Helpers.login;
import static net.ltgt.oidc.servlet.fixtures.Helpers.logoutFromIdP;

import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Application;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;
import jakarta.ws.rs.ext.ExceptionMapper;
import java.util.Set;
import net.ltgt.oidc.servlet.fixtures.WebDriverExtension;
import net.ltgt.oidc.servlet.rs.HasRole;
import net.ltgt.oidc.servlet.rs.HasRoleFeature;
import net.ltgt.oidc.servlet.rs.IsAuthenticated;
import net.ltgt.oidc.servlet.rs.IsAuthenticatedFilter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.openqa.selenium.WebDriver;

@ExtendWith(WebDriverExtension.class)
public class HasRoleTest {
  public static class TestApplication extends Application {
    @Override
    public Set<Class<?>> getClasses() {
      return Set.of(
          IsAuthenticatedFilter.class,
          HasRoleFeature.class,
          ForbiddenExceptionMapper.class,
          TestResource.class);
    }
  }

  public static class ForbiddenExceptionMapper implements ExceptionMapper<ForbiddenException> {
    @Override
    public Response toResponse(ForbiddenException exception) {
      if (exception.getResponse().hasEntity()) {
        return exception.getResponse();
      }
      return Response.fromResponse(exception.getResponse())
          .type(MediaType.TEXT_HTML_TYPE)
          .entity(
              """
              <!DOCTYPE html>
              <html lang="en">
              <head>
                  <meta charset="UTF-8">
                  <title>Forbidden</title>
              </head>
              <body>
                  <h1>Forbidden</h1>
              </body>
              </html>
              """)
          .build();
    }
  }

  @Path("/")
  public static class TestResource {
    @GET
    @Path("/private")
    @IsAuthenticated
    @Produces(MediaType.TEXT_HTML)
    public String private_(@Context SecurityContext securityContext) {
      return """
          <!DOCTYPE html>
          <html lang="en">
          <head>
              <meta charset="UTF-8">
              <title>Private page</title>
          </head>
          <body>
              <h1>Private page</h1>
          </body>
          </html>
          """;
    }

    @GET
    @Path("/admin")
    @HasRole("admin")
    @Produces(MediaType.TEXT_HTML)
    public String admin(@Context SecurityContext securityContext) {
      return """
          <!DOCTYPE html>
          <html lang="en">
          <head>
              <meta charset="UTF-8">
              <title>Admin page</title>
          </head>
          <body>
              <h1>Admin page</h1>
          </body>
          </html>
          """;
    }
  }

  @RegisterExtension
  public WebServerExtension server = new WebServerExtension(TestApplication.class);

  private final WebDriver driver;

  public HasRoleTest(WebDriver driver) {
    this.driver = driver;
  }

  @AfterEach
  public void logout() {
    logoutFromIdP(driver, server);
  }

  @Test
  public void hasRoleRequiresAuth() {
    driver.get(server.getURI("/admin"));

    login(driver, server, "admin", "admin");

    assertWithMessage("Should redirect back to application, authenticated")
        .that(driver.getCurrentUrl())
        .isEqualTo(server.getURI("/admin"));
    assertThat(driver.getTitle()).isEqualTo("Admin page");
  }

  @Test
  public void hasRoleChecksRole() {
    // First login on private
    driver.get(server.getURI("/private"));
    login(driver, server, "user", "user");

    assertWithMessage("Should redirect back to application, authenticated")
        .that(driver.getCurrentUrl())
        .isEqualTo(server.getURI("/private"));
    assertThat(driver.getTitle()).isEqualTo("Private page");

    // Then go to admin page
    driver.get(server.getURI("/admin"));

    assertThat(driver.getTitle()).contains("Forbidden");
  }
}
