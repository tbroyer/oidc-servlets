/*
 * Copyright © 2026 Thomas Broyer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
