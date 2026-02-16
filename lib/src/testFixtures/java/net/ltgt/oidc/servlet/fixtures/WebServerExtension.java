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
package net.ltgt.oidc.servlet.fixtures;

import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.fail;

import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import java.io.IOException;
import java.util.Objects;
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

public class WebServerExtension implements BeforeEachCallback, AfterEachCallback {
  public static final String CALLBACK_PATH = "/callback";
  public static final String LOGOUT_CALLBACK_PATH = "/logout_callback";
  public static final String BACK_CHANNEL_LOGOUT_CALLBACK_PATH = "/backchannel-logout";

  private final OIDCProviderMetadata providerMetadata;
  private final ClientAuthentication clientAuthentication;
  private final int port;
  private final Server server;

  public String getIssuer() {
    return providerMetadata.getIssuer().getValue();
  }

  public OIDCProviderMetadata getProviderMetadata() {
    return providerMetadata;
  }

  public ClientAuthentication getClientAuthentication() {
    return clientAuthentication;
  }

  public String getURI(String path) {
    return "http://app.localhost:" + port + path;
  }

  public WebServerExtension(
      BiFunction<Configuration, String, AuthenticationRedirector> authenticationRedirectorCreator,
      Consumer<ServletContextHandler> configure) {
    String issuer = requireNonNull(System.getProperty("test.issuer"));
    try {
      providerMetadata = OIDCProviderMetadata.resolve(new Issuer(issuer));
    } catch (GeneralException | IOException e) {
      throw (RuntimeException)
          fail("Can't load OIDC provider metadata. Is Keycloak started and configured?", e);
    }
    clientAuthentication =
        new ClientSecretBasic(
            new ClientID(Objects.requireNonNull(System.getProperty("test.clientId"))),
            new Secret(Objects.requireNonNull(System.getProperty("test.clientSecret"))));
    port = Integer.getInteger("test.port", 8000);
    var configuration = new Configuration(providerMetadata, clientAuthentication);
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
