package net.ltgt.oidc.servlet.functional;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth.assertWithMessage;
import static java.util.Objects.requireNonNull;
import static net.ltgt.oidc.servlet.functional.Helpers.login;
import static net.ltgt.oidc.servlet.functional.Helpers.logoutFromIdP;

import net.ltgt.oidc.servlet.BackchannelLogoutServlet;
import net.ltgt.oidc.servlet.BackchannelLogoutSessionListener;
import net.ltgt.oidc.servlet.InMemoryLoggedOutSessionStore;
import net.ltgt.oidc.servlet.IsAuthenticatedFilter;
import net.ltgt.oidc.servlet.LoggedOutSessionStore;
import org.eclipse.jetty.session.SessionConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WindowType;

@ExtendWith(WebDriverExtension.class)
public class BackChannelLogoutTest {
  @RegisterExtension
  public WebServerExtension server =
      new WebServerExtension(
          "simple",
          contextHandler -> {
            contextHandler.addEventListener(new BackchannelLogoutSessionListener());
            contextHandler.setAttribute(
                LoggedOutSessionStore.CONTEXT_ATTRIBUTE_NAME, new InMemoryLoggedOutSessionStore());
            contextHandler.addServlet(
                BackchannelLogoutServlet.class,
                WebServerExtension.BACK_CHANNEL_LOGOUT_CALLBACK_PATH);

            contextHandler.addFilter(IsAuthenticatedFilter.class, "/*", null);
          });

  @Test
  public void loginThenLogoutFromIdP(WebDriver driver) {
    driver.get(server.getURI("/"));

    login(driver, server, "user", "user");

    assertWithMessage("Should redirect back to application, authenticated")
        .that(driver.getCurrentUrl())
        .isEqualTo(server.getURI("/"));
    assertThat(driver.getTitle()).isEqualTo("Test page");

    var originalTab = driver.getWindowHandle();
    driver.switchTo().newWindow(WindowType.TAB);
    logoutFromIdP(driver, server);
    driver.close();
    driver.switchTo().window(originalTab);

    driver.navigate().refresh();
    assertWithMessage("Should have been logged out, and redirect to IdP")
        .that(driver.getCurrentUrl())
        .startsWith(server.getIssuer());
  }

  @Test
  public void loginForgetLoginAgainThenLogoutFromIdP(WebDriver driver) {
    driver.get(server.getURI("/"));

    login(driver, server, "user", "user");

    assertWithMessage("Should redirect back to application, authenticated")
        .that(driver.getCurrentUrl())
        .isEqualTo(server.getURI("/"));
    assertThat(driver.getTitle()).isEqualTo("Test page");

    var oldCookie = driver.manage().getCookieNamed(SessionConfig.__DefaultSessionCookie);
    assertThat(oldCookie).isNotNull();
    driver.manage().deleteCookieNamed(requireNonNull(oldCookie).getName());

    driver.navigate().refresh();

    assertWithMessage("Should redirect back to application, authenticated")
        .that(driver.getCurrentUrl())
        .isEqualTo(server.getURI("/"));
    assertThat(driver.getTitle()).isEqualTo("Test page");

    var newCookie = driver.manage().getCookieNamed(oldCookie.getName());
    assertThat(newCookie).isNotNull();
    assertThat(requireNonNull(newCookie).getValue()).isNotEqualTo(oldCookie.getName());

    var originalTab = driver.getWindowHandle();
    driver.switchTo().newWindow(WindowType.TAB);
    logoutFromIdP(driver, server);
    driver.close();
    driver.switchTo().window(originalTab);

    driver.navigate().refresh();
    assertWithMessage("Should have been logged out, and redirect to IdP")
        .that(driver.getCurrentUrl())
        .startsWith(server.getIssuer());

    driver.manage().getCookieNamed(oldCookie.getName());
    driver.manage().addCookie(oldCookie);

    driver.get(server.getURI("/"));
    assertWithMessage("Should have been logged out, and redirect to IdP")
        .that(driver.getCurrentUrl())
        .startsWith(server.getIssuer());
  }
}
