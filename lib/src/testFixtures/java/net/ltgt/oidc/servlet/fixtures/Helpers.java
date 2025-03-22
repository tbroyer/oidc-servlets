package net.ltgt.oidc.servlet.fixtures;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth.assertWithMessage;
import static org.openqa.selenium.support.ui.ExpectedConditions.not;
import static org.openqa.selenium.support.ui.ExpectedConditions.textToBePresentInElementLocated;
import static org.openqa.selenium.support.ui.ExpectedConditions.urlMatches;

import java.time.Duration;
import org.openqa.selenium.By;
import org.openqa.selenium.Keys;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.ui.WebDriverWait;

public class Helpers {
  public static void login(
      WebDriver driver, WebServerExtension server, String username, String password) {
    new WebDriverWait(driver, Duration.ofSeconds(2))
        .withMessage("Should redirect to IdP")
        .until(urlMatches("^\\Q" + server.getIssuer()));

    driver.findElement(By.id("username")).sendKeys(username);
    driver.findElement(By.id("password")).sendKeys(password, Keys.ENTER);
    new WebDriverWait(driver, Duration.ofSeconds(2))
        .until(not(urlMatches("^\\Q" + server.getIssuer())));
  }

  public static void logoutFromIdP(WebDriver driver, WebServerExtension server) {
    driver.get(server.getProviderMetadata().getEndSessionEndpointURI().toString());
    assertWithMessage("IdP presents logout page")
        .that(driver.getCurrentUrl())
        .isEqualTo(server.getProviderMetadata().getEndSessionEndpointURI().toString());
    assertThat(driver.findElement(By.id("kc-page-title")).getText()).contains("Logging out");
    var logout = driver.findElement(By.id("kc-logout"));
    logout.click();
    new WebDriverWait(driver, Duration.ofSeconds(2))
        .until(textToBePresentInElementLocated(By.id("kc-page-title"), "You are logged out"));
  }

  private Helpers() {}
}
