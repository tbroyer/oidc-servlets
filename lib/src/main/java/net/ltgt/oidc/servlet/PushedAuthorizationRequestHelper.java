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
package net.ltgt.oidc.servlet;

import static java.util.Objects.requireNonNull;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.PushedAuthorizationRequest;
import com.nimbusds.oauth2.sdk.PushedAuthorizationResponse;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequestSender;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.util.function.Consumer;
import org.jspecify.annotations.Nullable;

/**
 * Helps implement Pushed Authorization Requests.
 *
 * <p>Override {@link AuthenticationRedirector#sendRedirect(AuthenticationRequest, Consumer)} to
 * call {@link #sendRedirect(AuthenticationRequest, Consumer)} to secure the authentication request
 * in a JWT.
 *
 * {@snippet lang=java :
 * servletContext.setAttribute(
 *     AuthenticationRedirector.CONTEXT_ATTRIBUTE_NAME,
 *     new AuthenticationRedirector(configuration, callbackPath) {
 *       private final PushedAuthorizationRequestHelper parHelper = new PushedAuthorizationRequestHelper(configuration);
 *
 *       @Override
 *       public void sendRedirect(AuthenticationRequest authenticationRequest, Consumer<URI> sendRedirect) {
 *         parHelper.sendRedirect(authenticationRequest, sendRedirect);
 *       }
 *     });
 * }
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9126">OAuth 2.0 Pushed Authorization
 *     Requests</a>
 */
public class PushedAuthorizationRequestHelper {
  private final Configuration configuration;
  private final @Nullable HTTPRequestSender httpRequestSender;

  public PushedAuthorizationRequestHelper(Configuration configuration) {
    this(configuration, null);
  }

  public PushedAuthorizationRequestHelper(
      Configuration configuration, @Nullable HTTPRequestSender httpRequestSender) {
    this.configuration = requireNonNull(configuration);
    this.httpRequestSender = httpRequestSender;
  }

  public void sendRedirect(
      AuthenticationRequest authenticationRequest, Consumer<URI> sendRedirect) {
    var request =
        new PushedAuthorizationRequest(
            configuration.getProviderMetadata().getPushedAuthorizationRequestEndpointURI(),
            configuration.getClientAuthenticationSupplier().getClientAuthentication(),
            authenticationRequest);
    PushedAuthorizationResponse response;
    try {
      response = PushedAuthorizationResponse.parse(send(request.toHTTPRequest()));
    } catch (ParseException e) {
      throw new RuntimeException(e);
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
    if (!response.indicatesSuccess()) {
      throw new RuntimeException(response.toErrorResponse().getErrorObject().toString());
    }
    sendRedirect.accept(
        new AuthenticationRequest.Builder(
                response.toSuccessResponse().getRequestURI(), authenticationRequest.getClientID())
            .endpointURI(authenticationRequest.getEndpointURI())
            .build()
            .toURI());
  }

  private HTTPResponse send(HTTPRequest httpRequest) throws IOException {
    if (httpRequestSender != null) {
      return httpRequest.send(httpRequestSender);
    } else {
      return httpRequest.send();
    }
  }
}
