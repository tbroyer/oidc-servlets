package net.ltgt.oidc.servlet.functional;

import java.util.function.BiFunction;
import java.util.function.Consumer;
import net.ltgt.oidc.servlet.AuthenticationRedirector;
import net.ltgt.oidc.servlet.Configuration;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.util.resource.ResourceFactory;

public class WebServerExtension extends net.ltgt.oidc.servlet.fixtures.WebServerExtension {
  public WebServerExtension(String resourcePath, Consumer<ServletContextHandler> configure) {
    this(resourcePath, AuthenticationRedirector::new, configure);
  }

  public WebServerExtension(
      String resourcePath,
      BiFunction<Configuration, String, AuthenticationRedirector> authenticationRedirectorCreator,
      Consumer<ServletContextHandler> configure) {
    super(
        authenticationRedirectorCreator,
        contextHandler -> {
          // Jetty ClassLoaderResource works in such a way that for welcome files the directory must
          // only match in the same JAR or directory as the welcome file, so all resources here are
          // in a folder that will uniquely be in src/functionalTest/resources.
          contextHandler.setBaseResource(
              ResourceFactory.of(contextHandler)
                  .newClassLoaderResource(
                      "/net/ltgt/oidc/servlet/functional/web-resources/" + resourcePath));
          configure.accept(contextHandler);
        });
  }
}
