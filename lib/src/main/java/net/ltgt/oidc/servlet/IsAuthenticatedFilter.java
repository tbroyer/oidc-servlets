package net.ltgt.oidc.servlet;

import jakarta.servlet.http.HttpServletRequest;

public class IsAuthenticatedFilter extends AbstractAuthorizationFilter {

  @Override
  protected boolean isAuthorized(HttpServletRequest req) {
    return req.getUserPrincipal() != null;
  }
}