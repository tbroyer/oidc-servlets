package net.ltgt.oidc.servlet.functional;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth.assertWithMessage;
import static net.ltgt.oidc.servlet.functional.Helpers.login;
import static org.openqa.selenium.support.ui.ExpectedConditions.stalenessOf;

import java.time.Duration;
import net.ltgt.oidc.servlet.IsAuthenticatedFilter;
import net.ltgt.oidc.servlet.LogoutServlet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.ui.WebDriverWait;

@ExtendWith(WebDriverExtension.class)
public class SimpleTest {
  @RegisterExtension
  public WebServerExtension server =
      new WebServerExtension(
          "simple",
          contextHandler -> {
            contextHandler.addFilter(IsAuthenticatedFilter.class, "/*", null);
            contextHandler.addServlet(LogoutServlet.class, "/logout");
          });

  @Test
  public void loginThenLogout(WebDriver driver) {
    driver.get(server.getURI("/"));

    login(driver, server, "user", "user");

    assertWithMessage("Should redirect back to application, authenticated")
        .that(driver.getCurrentUrl())
        .isEqualTo(server.getURI("/"));
    assertThat(driver.getTitle()).isEqualTo("Test page");

    var logout = driver.findElement(By.id("logout"));
    logout.click();
    new WebDriverWait(driver, Duration.ofSeconds(2)).until(stalenessOf(logout));
    assertWithMessage("Should redirect to IdP for logout")
        .that(driver.getCurrentUrl())
        .startsWith(server.getIssuer());
    assertThat(driver.findElement(By.id("kc-page-title")).getText()).contains("You are logged out");
  }
}
