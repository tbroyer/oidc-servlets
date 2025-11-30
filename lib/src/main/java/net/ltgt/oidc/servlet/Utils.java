package net.ltgt.oidc.servlet;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequestSender;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.op.ReadOnlyOIDCProviderMetadata;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.MalformedURLException;
import java.net.URI;
import java.util.Map;

public class Utils {

  /**
   * The name of the {@linkplain jakarta.servlet.ServletContext#setAttribute servlet context
   * attribute} to register a {@link HTTPRequestSender} to be used to send requests to the OpenID
   * Provider.
   */
  public static final String HTTP_REQUEST_SENDER_CONTEXT_ATTRIBUTE_NAME =
      Utils.class.getName() + "#" + HTTPRequestSender.class.getName();

  /**
   * The name of the {@linkplain jakarta.servlet.ServletContext#setAttribute servlet context
   * attribute} to register a {@link JWKSource} to be used to validate JWT signatures.
   */
  public static final String JWK_SOURCE_CONTEXT_ATTRIBUTE_NAME =
      Utils.class.getName() + "#" + JWKSource.class.getName();

  /**
   * The name of the form parameter to pass a page's path to return to after login or logout.
   *
   * <p>The target page should be given as an absolute path (possibly with a query string), though a
   * full URL would be accepted as long as it's the same <a
   * href="https://datatracker.ietf.org/doc/html/rfc6454">origin</a>.
   *
   * @see LoginServlet
   * @see LogoutServlet
   */
  public static final String RETURN_TO_PARAMETER_NAME = "return-to";

  private Utils() {
    // non-instantiable
  }

  /**
   * Similar to {@link HttpServletResponse#sendRedirect(String)} but uses {@link
   * HttpServletResponse#SC_SEE_OTHER} rather than {@link HttpServletResponse#SC_FOUND}.
   */
  public static void sendRedirect(HttpServletResponse res, String location) {
    res.resetBuffer();
    res.setHeader("Location", location);
    res.setStatus(HttpServletResponse.SC_SEE_OTHER);
  }

  /** Returns whether the request is a navigation request. */
  static boolean isNavigation(HttpServletRequest req) {
    var fetchMode = req.getHeader("Sec-Fetch-Mode");
    // Sec-Fetch-Mode is only supported starting with Safari 16.4, so allow if absent
    // https://caniuse.com/mdn-http_headers_sec-fetch-mode
    return fetchMode == null || fetchMode.equals("navigate");
  }

  /** Returns whether the request uses a safe method. */
  static boolean isSafeMethod(HttpServletRequest req) {
    return req.getMethod().equalsIgnoreCase("GET") || req.getMethod().equalsIgnoreCase("HEAD");
  }

  /** Returns whether the request is <i>same origin</i>. */
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

  /**
   * Returns the {@link #RETURN_TO_PARAMETER_NAME} form parameter, validated and made relative to
   * the server root, or {@code /} as a fallback value (when the parameter is absent or has a
   * different <a href="https://datatracker.ietf.org/doc/html/rfc645">origin</a>.
   */
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

  /**
   * Returns the request's path and query-string, taking into account {@linkplain
   * RequestDispatcher#forward forwarded} requests to return the origin request URI.
   */
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

  /**
   * Returns the {@link #JWK_SOURCE_CONTEXT_ATTRIBUTE_NAME} servlet context attribute if it exists,
   * and otherwise create a {@link JWKSource} from the JWKSet URI and stores it in the servlet
   * context (so it can be shared between servlets).
   */
  static synchronized JWKSource<?> getJWKSource(ServletContext servletContext, URI jwkSetUri)
      throws ServletException {
    // XXX: don't synchronize on read and instead use double-checked locking?
    // There shouldn't be much contention so this is probably not worth it.
    JWKSource<?> jwkSource =
        (JWKSource<?>) servletContext.getAttribute(Utils.JWK_SOURCE_CONTEXT_ATTRIBUTE_NAME);
    if (jwkSource == null) {
      try {
        jwkSource = JWKSourceBuilder.create(jwkSetUri.toURL()).build();
        servletContext.setAttribute(Utils.JWK_SOURCE_CONTEXT_ATTRIBUTE_NAME, jwkSource);
      } catch (MalformedURLException e) {
        throw new ServletException(e);
      }
    }
    return jwkSource;
  }

  /**
   * Resolves the {@link ReadOnlyOIDCProviderMetadata#getReadOnlyMtlsEndpointAliases()
   * mtls_endpoint_aliases} of the given provider metadata.
   *
   * @return the passed in object if it doesn't have {@code mtls_endpoint_aliases}, or a new
   *     provider metadata where the {@code mtls_endpoint_aliases} have been removed and merged into
   *     the top-level object.
   * @see Configuration
   */
  public static ReadOnlyOIDCProviderMetadata resolveMtlsEndpointAliases(
      ReadOnlyOIDCProviderMetadata original) {
    if (original.getReadOnlyMtlsEndpointAliases() == null) {
      return original;
    }
    var json = original.toJSONObject();
    @SuppressWarnings("unchecked")
    var mtlsEndpointAliases = (Map<String, ?>) json.remove("mtls_endpoint_aliases");
    json.putAll(mtlsEndpointAliases);
    try {
      return OIDCProviderMetadata.parse(json);
    } catch (ParseException e) {
      // This should never happen, as the original JSON had already been parsed
      throw new RuntimeException(e);
    }
  }
}
