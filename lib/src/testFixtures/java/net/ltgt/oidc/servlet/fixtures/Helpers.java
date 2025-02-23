package net.ltgt.oidc.servlet.fixtures;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth.assertWithMessage;
import static org.openqa.selenium.support.ui.ExpectedConditions.stalenessOf;

import java.time.Duration;
import org.openqa.selenium.By;
import org.openqa.selenium.Keys;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.ui.WebDriverWait;

public class Helpers {
  public static void login(
      WebDriver driver, WebServerExtension server, String username, String password) {
    assertWithMessage("Should redirect to IdP")
        .that(driver.getCurrentUrl())
        .startsWith(server.getIssuer());

    var usernameField = driver.findElement(By.id("username"));
    usernameField.sendKeys(username);
    driver.findElement(By.id("password")).sendKeys(password, Keys.ENTER);
    new WebDriverWait(driver, Duration.ofSeconds(2)).until(stalenessOf(usernameField));
  }

  public static void logoutFromIdP(WebDriver driver, WebServerExtension server) {
    driver.get(server.getProviderMetadata().getEndSessionEndpointURI().toString());
    assertWithMessage("IdP presents logout page")
        .that(driver.getCurrentUrl())
        .isEqualTo(server.getProviderMetadata().getEndSessionEndpointURI().toString());
    assertThat(driver.findElement(By.id("kc-page-title")).getText()).contains("Logging out");
    var logout = driver.findElement(By.id("kc-logout"));
    logout.click();
    new WebDriverWait(driver, Duration.ofSeconds(2)).until(stalenessOf(logout));
    assertThat(driver.findElement(By.id("kc-page-title")).getText()).contains("You are logged out");
  }

  private Helpers() {}
}
