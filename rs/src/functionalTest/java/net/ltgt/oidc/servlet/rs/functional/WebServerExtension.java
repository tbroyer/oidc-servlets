package net.ltgt.oidc.servlet.rs.functional;

import jakarta.ws.rs.core.Application;
import net.ltgt.oidc.servlet.AuthenticationRedirector;
import org.jboss.resteasy.plugins.server.servlet.HttpServlet30Dispatcher;

public class WebServerExtension extends net.ltgt.oidc.servlet.fixtures.WebServerExtension {

  public WebServerExtension(Class<? extends Application> applicationClass) {
    super(
        AuthenticationRedirector::new,
        contextHandler -> {
          contextHandler
              .addServlet(HttpServlet30Dispatcher.class, "/*")
              .setInitParameter("jakarta.ws.rs.Application", applicationClass.getName());
        });
  }
}
