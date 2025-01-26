package net.ltgt.oidc.servlet;

import jakarta.servlet.http.HttpServletRequest;

/** Ensures the user {@linkplain HttpServletRequest#getUserPrincipal is authenticated}. */
public class IsAuthenticatedFilter extends AbstractAuthorizationFilter {

  public IsAuthenticatedFilter() {}

  /**
   * Constructs a filter with the given authentication redirector.
   *
   * <p>When this constructor is used, the {@linkplain
   * AuthenticationRedirector#CONTEXT_ATTRIBUTE_NAME servlet context attribute} won't be read.
   */
  public IsAuthenticatedFilter(AuthenticationRedirector authenticationRedirector) {
    super(authenticationRedirector);
  }

  @Override
  protected boolean isAuthorized(HttpServletRequest req) {
    return req.getUserPrincipal() != null;
  }
}
