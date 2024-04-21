package net.ltgt.oidc.servlet;

import static java.util.Objects.requireNonNull;

import com.google.errorprone.annotations.ForOverride;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

public class HasRoleFilter extends AbstractAuthorizationFilter {

  public static final String ROLE = "role";

  private String role;

  public HasRoleFilter() {}

  public HasRoleFilter(String role) {
    this.role = role;
  }

  @Override
  public void init() throws ServletException {
    super.init();
    if (role == null) {
      role = requireNonNull(getInitParameter(ROLE));
    }
  }

  @Override
  protected final boolean isAuthorized(HttpServletRequest req) {
    return req.isUserInRole(role);
  }

  @ForOverride
  @Override
  protected void redirectToAuthenticationEndpoint(HttpServletRequest req, HttpServletResponse res)
      throws IOException, ServletException {
    if (req.getUserPrincipal() == null) {
      super.redirectToAuthenticationEndpoint(req, res);
    } else {
      res.sendError(HttpServletResponse.SC_FORBIDDEN);
    }
  }

  @ForOverride
  @Override
  protected void sendUnauthorized(HttpServletRequest req, HttpServletResponse res)
      throws IOException, ServletException {
    if (req.getUserPrincipal() == null) {
      super.sendUnauthorized(req, res);
    } else {
      res.sendError(HttpServletResponse.SC_FORBIDDEN);
    }
  }
}
