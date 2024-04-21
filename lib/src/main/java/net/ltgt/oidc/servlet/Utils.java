package net.ltgt.oidc.servlet;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URI;

public class Utils {

  public static final String RETURN_TO_PARAMETER_NAME = "return-to";

  private Utils() {
    // non-instantiable
  }

  /**
   * Same as {@link HttpServletResponse#sendRedirect(String)} but uses {@link
   * HttpServletResponse#SC_SEE_OTHER} rather than {@link HttpServletResponse#SC_FOUND}.
   */
  static void sendRedirect(HttpServletResponse res, String location) {
    res.resetBuffer();
    res.setHeader("Location", location);
    res.setStatus(HttpServletResponse.SC_SEE_OTHER);
  }

  static boolean isNavigation(HttpServletRequest req) {
    var fetchMode = req.getHeader("Sec-Fetch-Mode");
    // Sec-Fetch-Mode is only supported starting with Safari 16.4, so allow if absent
    // https://caniuse.com/mdn-http_headers_sec-fetch-mode
    return fetchMode == null || fetchMode.equals("navigate");
  }

  static boolean isSafeMethod(HttpServletRequest req) {
    return req.getMethod().equalsIgnoreCase("GET") || req.getMethod().equalsIgnoreCase("HEAD");
  }

  static boolean isSameOrigin(HttpServletRequest req) {
    var fetchSite = req.getHeader("Sec-Fetch-Site");
    // Sec-Fetch-Site is only supported starting with Safari 16.4, so fallback if absent
    // https://caniuse.com/mdn-http_headers_sec-fetch-site
    if (fetchSite != null && fetchSite.equals("same-origin")) {
      return true;
    }
    var actualOrigin = req.getHeader("Origin");
    // Origin might be absent (e.g. for safe methods), so fallback to referer
    if (actualOrigin == null) {
      try {
        actualOrigin = URI.create(req.getHeader("Referer")).resolve("/").toString();
      } catch (NullPointerException | IllegalArgumentException e) {
        return false;
      }
    } else {
      actualOrigin += "/";
    }
    return req.getRequestURL().toString().startsWith(actualOrigin);
  }

  static String getReturnToParameter(HttpServletRequest req) {
    var returnTo = req.getParameter(RETURN_TO_PARAMETER_NAME);
    if (returnTo == null) {
      return "/";
    }
    var rootUri = URI.create(req.getRequestURL().toString()).resolve("/");
    var returnToUri = rootUri.resolve(returnTo);
    var relativized = rootUri.relativize(returnToUri);
    if (relativized.equals(returnToUri)) {
      return "/";
    }
    return "/" + relativized.toASCIIString();
  }

  public static String getRequestUri(HttpServletRequest req) {
    String requestUri, queryString;
    if (req.getDispatcherType() == DispatcherType.FORWARD) {
      requestUri = (String) req.getAttribute(RequestDispatcher.FORWARD_REQUEST_URI);
      queryString = (String) req.getAttribute(RequestDispatcher.FORWARD_QUERY_STRING);
    } else {
      requestUri = req.getRequestURI();
      queryString = req.getQueryString();
    }
    return queryString == null ? requestUri : requestUri + "?" + queryString;
  }
}
