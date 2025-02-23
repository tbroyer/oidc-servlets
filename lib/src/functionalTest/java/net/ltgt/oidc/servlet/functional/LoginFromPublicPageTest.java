package net.ltgt.oidc.servlet.functional;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth.assertWithMessage;
import static net.ltgt.oidc.servlet.fixtures.Helpers.login;
import static net.ltgt.oidc.servlet.fixtures.Helpers.logoutFromIdP;

import net.ltgt.oidc.servlet.IsAuthenticatedFilter;
import net.ltgt.oidc.servlet.LoginServlet;
import net.ltgt.oidc.servlet.fixtures.WebDriverExtension;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;

@ExtendWith(WebDriverExtension.class)
public class LoginFromPublicPageTest {
  @RegisterExtension
  public WebServerExtension server =
      new WebServerExtension(
          "public-page",
          contextHandler -> {
            contextHandler.addServlet(LoginServlet.class, "/login");
            contextHandler.addFilter(IsAuthenticatedFilter.class, "/private.html", null);
          });

  private final WebDriver driver;

  public LoginFromPublicPageTest(WebDriver driver) {
    this.driver = driver;
  }

  @AfterEach
  public void logout() {
    logoutFromIdP(driver, server);
  }

  @Test
  public void checkPrivateRequiresAuth() {
    // This is not a real test, it actually checks the test harness
    driver.get(server.getURI("/private.html"));
    assertWithMessage("Should redirect to IdP")
        .that(driver.getCurrentUrl())
        .startsWith(server.getIssuer());
  }

  @Test
  public void loginWithLink() {
    driver.get(server.getURI("/"));
    assertThat(driver.getTitle()).isEqualTo("Test page");

    driver.findElement(By.linkText("Login")).click();

    login(driver, server, "user", "user");

    assertWithMessage("Should redirect back to application, authenticated")
        .that(driver.getCurrentUrl())
        .isEqualTo(server.getURI("/private.html"));
    assertThat(driver.getTitle()).isEqualTo("Private page");
  }

  @Test
  public void loginWithForm() {
    driver.get(server.getURI("/"));
    assertThat(driver.getTitle()).isEqualTo("Test page");

    driver.findElement(By.id("login")).click();

    login(driver, server, "user", "user");

    assertWithMessage("Should redirect back to application, authenticated")
        .that(driver.getCurrentUrl())
        .isEqualTo(server.getURI("/private.html"));
    assertThat(driver.getTitle()).isEqualTo("Private page");
  }
}
