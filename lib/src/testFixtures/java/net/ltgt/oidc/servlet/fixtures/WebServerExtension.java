package net.ltgt.oidc.servlet.fixtures;

import static java.util.Objects.requireNonNull;

import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import java.io.IOException;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import net.ltgt.oidc.servlet.AuthenticationRedirector;
import net.ltgt.oidc.servlet.CallbackServlet;
import net.ltgt.oidc.servlet.Configuration;
import net.ltgt.oidc.servlet.KeycloakUserPrincipal;
import net.ltgt.oidc.servlet.UserFilter;
import net.ltgt.oidc.servlet.UserPrincipalFactory;
import org.eclipse.jetty.ee10.servlet.DefaultServlet;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.server.Server;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.opentest4j.TestAbortedException;

public class WebServerExtension implements BeforeEachCallback, AfterEachCallback {
  public static final String CALLBACK_PATH = "/callback";
  public static final String LOGOUT_CALLBACK_PATH = "/logout_callback";
  public static final String BACK_CHANNEL_LOGOUT_CALLBACK_PATH = "/backchannel-logout";

  private final OIDCProviderMetadata providerMetadata;
  private final int port;
  private final Server server;

  public String getIssuer() {
    return providerMetadata.getIssuer().getValue();
  }

  public OIDCProviderMetadata getProviderMetadata() {
    return providerMetadata;
  }

  public String getURI(String path) {
    return "http://localhost:" + port + path;
  }

  public WebServerExtension(
      BiFunction<Configuration, String, AuthenticationRedirector> authenticationRedirectorCreator,
      Consumer<ServletContextHandler> configure) {
    String issuer = requireNonNull(System.getProperty("test.issuer"));
    try {
      providerMetadata = OIDCProviderMetadata.resolve(new Issuer(issuer));
    } catch (GeneralException | IOException e) {
      throw new TestAbortedException(
          "Can't load OIDC provider metadata. Is Keycloak started and configured?", e);
    }
    port = Integer.getInteger("test.port", 8000);
    var configuration =
        new Configuration(
            providerMetadata,
            new ClientSecretBasic(
                new ClientID(requireNonNull(System.getProperty("test.clientId"))),
                new Secret(requireNonNull(System.getProperty("test.clientSecret")))));
    server = new Server(port);
    var contextHandler = new ServletContextHandler(ServletContextHandler.SESSIONS);
    server.setHandler(contextHandler);

    contextHandler.setAttribute(Configuration.CONTEXT_ATTRIBUTE_NAME, configuration);
    contextHandler.setAttribute(
        AuthenticationRedirector.CONTEXT_ATTRIBUTE_NAME,
        authenticationRedirectorCreator.apply(configuration, CALLBACK_PATH));
    contextHandler.setAttribute(
        UserPrincipalFactory.CONTEXT_ATTRIBUTE_NAME, KeycloakUserPrincipal.FACTORY);

    contextHandler.addFilter(UserFilter.class, "/*", null);
    contextHandler.addServlet(CallbackServlet.class, CALLBACK_PATH);

    configure.accept(contextHandler);

    contextHandler.addServlet(DefaultServlet.class, "/");
  }

  @Override
  public void beforeEach(ExtensionContext context) throws Exception {
    server.start();
  }

  @Override
  public void afterEach(ExtensionContext context) throws Exception {
    server.stop();
  }
}
