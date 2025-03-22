package net.ltgt.oidc.servlet.functional;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth.assertWithMessage;
import static java.util.Objects.requireNonNull;
import static net.ltgt.oidc.servlet.fixtures.Helpers.login;
import static net.ltgt.oidc.servlet.fixtures.Helpers.logoutFromIdP;
import static org.openqa.selenium.support.ui.ExpectedConditions.urlMatches;

import java.time.Duration;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import net.ltgt.oidc.servlet.BackchannelLogoutServlet;
import net.ltgt.oidc.servlet.BackchannelLogoutSessionListener;
import net.ltgt.oidc.servlet.InMemoryLoggedOutSessionStore;
import net.ltgt.oidc.servlet.IsAuthenticatedFilter;
import net.ltgt.oidc.servlet.LoggedOutSessionStore;
import net.ltgt.oidc.servlet.fixtures.WebDriverExtension;
import org.eclipse.jetty.session.SessionConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WindowType;
import org.openqa.selenium.support.ui.WebDriverWait;

@ExtendWith(WebDriverExtension.class)
public class BackChannelLogoutTest {
  AtomicBoolean backchannelLoggedOut = new AtomicBoolean();

  @RegisterExtension
  public WebServerExtension server =
      new WebServerExtension(
          "simple",
          contextHandler -> {
            contextHandler.addEventListener(new BackchannelLogoutSessionListener());
            contextHandler.setAttribute(
                LoggedOutSessionStore.CONTEXT_ATTRIBUTE_NAME,
                new InMemoryLoggedOutSessionStore() {
                  @Override
                  protected void doLogout(Set<String> sessionIds) {
                    backchannelLoggedOut.set(true);
                  }
                });
            contextHandler.addServlet(
                BackchannelLogoutServlet.class,
                WebServerExtension.BACK_CHANNEL_LOGOUT_CALLBACK_PATH);

            contextHandler.addFilter(IsAuthenticatedFilter.class, "/*", null);
          });

  private void logoutFromIdPInOtherTab(WebDriver driver) {
    backchannelLoggedOut.set(false);

    var originalTab = driver.getWindowHandle();
    driver.switchTo().newWindow(WindowType.TAB);
    logoutFromIdP(driver, server);
    driver.close();

    driver.switchTo().window(originalTab);

    new WebDriverWait(driver, Duration.ofSeconds(5))
        .withMessage("Should be called back from IdP in backchannel logout callback")
        .until(ignored -> backchannelLoggedOut.get());
  }

  @Test
  public void loginThenLogoutFromIdP(WebDriver driver) {
    driver.get(server.getURI("/"));

    login(driver, server, "user", "user");

    assertWithMessage("Should redirect back to application, authenticated")
        .that(driver.getCurrentUrl())
        .isEqualTo(server.getURI("/"));
    assertThat(driver.getTitle()).isEqualTo("Test page");

    logoutFromIdPInOtherTab(driver);

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

    logoutFromIdPInOtherTab(driver);

    driver.navigate().refresh();

    new WebDriverWait(driver, Duration.ofSeconds(5))
        .withMessage("Should have been logged out, and redirect to IdP")
        .until(urlMatches("^\\Q" + server.getIssuer()));

    driver.manage().addCookie(oldCookie);
    driver.get(server.getURI("/"));

    new WebDriverWait(driver, Duration.ofSeconds(5))
        .withMessage("Should have been logged out, and redirect to IdP")
        .until(urlMatches("^\\Q" + server.getIssuer()));
  }
}
