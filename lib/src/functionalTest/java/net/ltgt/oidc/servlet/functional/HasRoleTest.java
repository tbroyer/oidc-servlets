package net.ltgt.oidc.servlet.functional;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth.assertWithMessage;
import static net.ltgt.oidc.servlet.fixtures.Helpers.login;
import static net.ltgt.oidc.servlet.fixtures.Helpers.logoutFromIdP;

import net.ltgt.oidc.servlet.HasRoleFilter;
import net.ltgt.oidc.servlet.IsAuthenticatedFilter;
import net.ltgt.oidc.servlet.fixtures.WebDriverExtension;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.openqa.selenium.WebDriver;

@ExtendWith(WebDriverExtension.class)
public class HasRoleTest {
  @RegisterExtension
  public WebServerExtension server =
      new WebServerExtension(
          "admin",
          contextHandler -> {
            contextHandler.addFilter(IsAuthenticatedFilter.class, "/private.html", null);
            contextHandler.addFilter(new HasRoleFilter("admin"), "/admin.html", null);
          });

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
    driver.get(server.getURI("/admin.html"));

    login(driver, server, "admin", "admin");

    assertWithMessage("Should redirect back to application, authenticated")
        .that(driver.getCurrentUrl())
        .isEqualTo(server.getURI("/admin.html"));
    assertThat(driver.getTitle()).isEqualTo("Admin page");
  }

  @Test
  public void hasRoleChecksRole() {
    // First login on private
    driver.get(server.getURI("/private.html"));
    login(driver, server, "user", "user");

    assertWithMessage("Should redirect back to application, authenticated")
        .that(driver.getCurrentUrl())
        .isEqualTo(server.getURI("/private.html"));
    assertThat(driver.getTitle()).isEqualTo("Private page");

    // Then go to admin page
    driver.get(server.getURI("/admin.html"));

    assertThat(driver.getTitle()).contains("Forbidden");
  }
}
