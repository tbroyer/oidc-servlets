package net.ltgt.oidc.servlet.functional;

import static com.google.common.truth.Truth.assertThat;
import static net.ltgt.oidc.servlet.functional.Helpers.login;
import static org.openqa.selenium.support.ui.ExpectedConditions.stalenessOf;

import java.time.Duration;
import net.ltgt.oidc.servlet.LoginServlet;
import net.ltgt.oidc.servlet.LogoutCallbackServlet;
import net.ltgt.oidc.servlet.LogoutServlet;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.ui.WebDriverWait;

public class LogoutTest {

  @Nested
  @ExtendWith(WebDriverExtension.class)
  public class WithoutLogoutState {
    @RegisterExtension
    public WebServerExtension server =
        new WebServerExtension(
            "logout",
            contextHandler -> {
              contextHandler.addServlet(LoginServlet.class, "/login");
              contextHandler.addServlet(new LogoutServlet("/"), "/logout");
            });

    @Test
    public void logout(WebDriver driver) {
      // index's login link redirects to other.html
      // other.html's logout form should redirect to index
      driver.get(server.getURI("/"));
      assertThat(driver.getTitle()).isEqualTo("Test page");

      driver.findElement(By.linkText("Login")).click();

      login(driver, server, "user", "user");

      assertThat(driver.getCurrentUrl()).isEqualTo(server.getURI("/other.html"));

      var logout = driver.findElement(By.id("logout"));
      logout.click();
      new WebDriverWait(driver, Duration.ofSeconds(2)).until(stalenessOf(logout));

      assertThat(driver.getCurrentUrl()).isEqualTo(server.getURI("/"));
    }
  }

  @Nested
  @ExtendWith(WebDriverExtension.class)
  public class WithLogoutState {
    @RegisterExtension
    public WebServerExtension server =
        new WebServerExtension(
            "logout",
            contextHandler -> {
              contextHandler.addServlet(LoginServlet.class, "/login");
              contextHandler.addServlet(
                  new LogoutServlet(WebServerExtension.LOGOUT_CALLBACK_PATH, true), "/logout");
              contextHandler.addServlet(
                  LogoutCallbackServlet.class, WebServerExtension.LOGOUT_CALLBACK_PATH);
            });

    @Test
    public void logout(WebDriver driver) {
      // other.html's login link redirects to index
      // index's logout form redirects to other.html
      driver.get(server.getURI("/other.html"));
      assertThat(driver.getTitle()).isEqualTo("Test page");

      driver.findElement(By.linkText("Login")).click();

      login(driver, server, "user", "user");

      assertThat(driver.getCurrentUrl()).isEqualTo(server.getURI("/"));

      var logout = driver.findElement(By.id("logout"));
      logout.click();
      new WebDriverWait(driver, Duration.ofSeconds(2)).until(stalenessOf(logout));

      assertThat(driver.getCurrentUrl()).isEqualTo(server.getURI("/other.html"));
    }
  }
}
