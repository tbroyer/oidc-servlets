package net.ltgt.oidc.servlet.example.jetty;

import static jakarta.servlet.DispatcherType.FORWARD;
import static jakarta.servlet.DispatcherType.REQUEST;
import static java.util.Objects.requireNonNull;

import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import jakarta.servlet.ServletContext;
import java.nio.file.Files;
import java.util.EnumSet;
import net.ltgt.oidc.servlet.AuthenticationRedirector;
import net.ltgt.oidc.servlet.BackchannelLogoutServlet;
import net.ltgt.oidc.servlet.BackchannelLogoutSessionListener;
import net.ltgt.oidc.servlet.CallbackServlet;
import net.ltgt.oidc.servlet.Configuration;
import net.ltgt.oidc.servlet.HasRoleFilter;
import net.ltgt.oidc.servlet.InMemoryLoggedOutSessionStore;
import net.ltgt.oidc.servlet.IsAuthenticatedFilter;
import net.ltgt.oidc.servlet.KeycloakUserPrincipal;
import net.ltgt.oidc.servlet.LoggedOutSessionStore;
import net.ltgt.oidc.servlet.LoginServlet;
import net.ltgt.oidc.servlet.LogoutCallbackServlet;
import net.ltgt.oidc.servlet.LogoutServlet;
import net.ltgt.oidc.servlet.UserFilter;
import org.eclipse.jetty.ee10.apache.jsp.JettyJasperInitializer;
import org.eclipse.jetty.ee10.jsp.JettyJspServlet;
import org.eclipse.jetty.ee10.servlet.DefaultServlet;
import org.eclipse.jetty.ee10.servlet.ServletContainerInitializerHolder;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;
import org.eclipse.jetty.server.Server;

public class Main {

  private static final String CALLBACK_PATH = "/callback";
  private static final String LOGOUT_CALLBACK_PATH = "/logout_callback";
  private static final String DEFAULT_SERVLET_NAME = "default";

  public static void main(String[] args) throws Exception {
    var configuration =
        new Configuration(
            OIDCProviderMetadata.resolve(
                new Issuer(requireNonNull(System.getProperty("example.issuer")))),
            new ClientSecretBasic(
                new ClientID(requireNonNull(System.getProperty("example.clientId"))),
                new Secret(requireNonNull(System.getProperty("example.clientSecret")))),
            KeycloakUserPrincipal::new);

    var server = new Server(Integer.getInteger("example.port", 8000));

    var contextHandler = new ServletContextHandler(ServletContextHandler.SESSIONS);
    contextHandler.setBaseResourceAsString(args[0]);
    contextHandler.setProtectedTargets(new String[] {"/WEB-INF"});
    server.setHandler(contextHandler);

    contextHandler.setAttribute(Configuration.CONTEXT_ATTRIBUTE_NAME, configuration);
    contextHandler.setAttribute(
        AuthenticationRedirector.CONTEXT_ATTRIBUTE_NAME,
        new AuthenticationRedirector(configuration, CALLBACK_PATH));
    contextHandler.setAttribute(
        LoggedOutSessionStore.CONTEXT_ATTRIBUTE_NAME, new InMemoryLoggedOutSessionStore());

    contextHandler.addEventListener(new BackchannelLogoutSessionListener());

    contextHandler.addFilter(UserFilter.class, "/*", null);
    contextHandler.addServlet(CallbackServlet.class, CALLBACK_PATH);
    contextHandler.addServlet(new LogoutServlet(LOGOUT_CALLBACK_PATH, true), "/logout");
    contextHandler.addServlet(LogoutCallbackServlet.class, LOGOUT_CALLBACK_PATH);
    contextHandler.addServlet(BackchannelLogoutServlet.class, "/backchannel-logout");
    contextHandler.addServlet(LoginServlet.class, "/login");

    contextHandler.addFilter(IsAuthenticatedFilter.class, "/private/*", null);
    contextHandler.addFilter(new HasRoleFilter("admin"), "/admin/*", null);

    contextHandler.addFilter(
        IsAuthenticatedFilter.class, "/spa/index.jsp", EnumSet.of(REQUEST, FORWARD));
    var spaFilter = contextHandler.addFilter(SpaFilter.class, "/spa/*", null);
    spaFilter.setAsyncSupported(false);
    spaFilter.setInitParameter(SpaFilter.FORWARD_PATH, "/spa/");
    spaFilter.setInitParameter(SpaFilter.DEFAULT_SERVLET_NAME, DEFAULT_SERVLET_NAME);

    contextHandler.addServlet(new ServletHolder(DEFAULT_SERVLET_NAME, DefaultServlet.class), "/");

    contextHandler.addServletContainerInitializer(
        new ServletContainerInitializerHolder(JettyJasperInitializer.class));
    contextHandler.addServlet(JettyJspServlet.class, "*.jsp");
    var tempdir = Files.createTempDirectory("jsp").toFile();
    tempdir.deleteOnExit();
    contextHandler.setAttribute(ServletContext.TEMPDIR, tempdir);
    // JSP requires that an explicit classloader is set.
    contextHandler.setClassLoader(Thread.currentThread().getContextClassLoader());

    server.setStopAtShutdown(true);
    server.start();
    server.join();
  }
}
