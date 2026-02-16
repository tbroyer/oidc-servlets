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
