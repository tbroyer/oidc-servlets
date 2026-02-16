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
package net.ltgt.oidc.servlet.rs;

import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Response;
import java.util.function.Consumer;
import net.ltgt.oidc.servlet.AuthenticationRedirector;
import net.ltgt.oidc.servlet.CallbackServlet;
import org.jspecify.annotations.Nullable;

/** Utility constants and methods. */
public class Utils {

  private Utils() {
    // non-instantiable
  }

  /**
   * Redirects to the OpenID Provider, returning to the given page when coming back.
   *
   * <p>This is equivalent to {@code redirectToAuthenticationEndpoint(req, res, returnTo, null)}.
   */
  public static void redirectToAuthenticationEndpoint(
      AuthenticationRedirector authenticationRedirector,
      ContainerRequestContext containerRequestContext,
      HttpServletRequest req,
      String returnTo) {
    redirectToAuthenticationEndpoint(
        authenticationRedirector, containerRequestContext, req, returnTo, null);
  }

  /**
   * Redirects to the OpenID Provider, returning to the given page when coming back, and possibly
   * configuring the authentication request further.
   *
   * <p>The target page should be given as an absolute path (possibly with a query string), though a
   * full URL would be accepted as long as it's the same <a
   * href="https://datatracker.ietf.org/doc/html/rfc6454">origin</a>. It will be saved in the
   * session to be redirected to from the {@link CallbackServlet}.
   */
  public static void redirectToAuthenticationEndpoint(
      AuthenticationRedirector authenticationRedirector,
      ContainerRequestContext containerRequestContext,
      HttpServletRequest req,
      String returnTo,
      @Nullable Consumer<AuthenticationRequest.Builder> configureAuthenticationRequest) {
    authenticationRedirector.redirectToAuthenticationEndpoint(
        req.getSession(),
        returnTo,
        configureAuthenticationRequest,
        containerRequestContext.getUriInfo().getRequestUri(),
        uri -> containerRequestContext.abortWith(Response.seeOther(uri).build()));
  }

  /** Returns whether the request is a navigation request. */
  static boolean isNavigation(ContainerRequestContext containerRequestContext) {
    var fetchMode = containerRequestContext.getHeaderString("Sec-Fetch-Mode");
    // Sec-Fetch-Mode is only supported starting with Safari 16.4, so allow if absent
    // https://caniuse.com/mdn-http_headers_sec-fetch-mode
    return fetchMode == null || fetchMode.equals("navigate");
  }

  /** Returns whether the request uses a safe method. */
  static boolean isSafeMethod(ContainerRequestContext containerRequestContext) {
    return containerRequestContext.getMethod().equalsIgnoreCase("GET")
        || containerRequestContext.getMethod().equalsIgnoreCase("HEAD");
  }
}
