package net.ltgt.oidc.servlet.rs;

import jakarta.ws.rs.container.ContainerRequestContext;

class Utils {
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
