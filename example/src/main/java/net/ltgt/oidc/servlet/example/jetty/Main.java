package net.ltgt.oidc.servlet.example.jetty;

import static java.util.Objects.requireNonNull;

import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import jakarta.servlet.ServletContext;
import java.nio.file.Files;
import org.eclipse.jetty.ee10.apache.jsp.JettyJasperInitializer;
import org.eclipse.jetty.ee10.jsp.JettyJspServlet;
import org.eclipse.jetty.ee10.servlet.DefaultServlet;
import org.eclipse.jetty.ee10.servlet.ServletContainerInitializerHolder;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.server.Server;

public class Main {

  public static void main(String[] args) throws Exception {
    var configuration =
        new Configuration(
            OIDCProviderMetadata.resolve(
                new Issuer(requireNonNull(System.getProperty("example.issuer")))),
            "/callback",
            new ClientSecretBasic(
                new ClientID(requireNonNull(System.getProperty("example.clientId"))),
                new Secret(requireNonNull(System.getProperty("example.clientSecret")))));

    var server = new Server(Integer.getInteger("example.port", 8000));

    var contextHandler = new ServletContextHandler(ServletContextHandler.SESSIONS);
    contextHandler.setBaseResourceAsString(args[0]);
    contextHandler.setProtectedTargets(new String[] {"/WEB-INF"});
    server.setHandler(contextHandler);

    contextHandler.setAttribute(Configuration.CONTEXT_ATTRIBUTE_NAME, configuration);

    contextHandler.addFilter(UserFilter.class, "/*", null);
    contextHandler.addServlet(CallbackServlet.class, configuration.callbackPath());
    contextHandler.addServlet(new LogoutServlet(true), "/logout");
    // TODO: back-channel logout
    // contextHandler.addServlet(BackChannelLogoutServlet.class, "/backchannel-logout");

    contextHandler.addFilter(IsAuthenticatedFilter.class, "/private/*", null);

    contextHandler.addServlet(DefaultServlet.class, "/");

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
