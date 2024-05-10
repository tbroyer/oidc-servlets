package net.ltgt.oidc.servlet.functional;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth.assertWithMessage;

import org.openqa.selenium.By;
import org.openqa.selenium.Keys;
import org.openqa.selenium.WebDriver;

public class Helpers {
  public static void login(
      WebDriver driver, WebServerExtension server, String username, String password) {
    assertWithMessage("Should redirect to IdP")
        .that(driver.getCurrentUrl())
        .startsWith(server.getIssuer());

    driver.findElement(By.id("username")).sendKeys(username);
    driver.findElement(By.id("password")).sendKeys(password, Keys.ENTER);
  }

  public static void logoutFromIdP(WebDriver driver, WebServerExtension server) {
    driver.get(server.getProviderMetadata().getEndSessionEndpointURI().toString());
    assertWithMessage("IdP presents logout page")
        .that(driver.getCurrentUrl())
        .isEqualTo(server.getProviderMetadata().getEndSessionEndpointURI().toString());
    assertThat(driver.findElement(By.id("kc-page-title")).getText()).contains("Logging out");
    driver.findElement(By.id("kc-logout")).click();
    assertThat(driver.findElement(By.id("kc-page-title")).getText()).contains("You are logged out");
  }

  private Helpers() {}
}
