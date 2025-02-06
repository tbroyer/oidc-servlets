package net.ltgt.oidc.servlet;

import static java.util.Objects.requireNonNull;

import com.google.errorprone.annotations.OverridingMethodsMustInvokeSuper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Ensures the user {@linkplain HttpServletRequest#isUserInRole has a given role}.
 *
 * <p>This filter should be installed <i>after</i> the {@link UserFilter} as it relies on {@link
 * HttpServletRequest#isUserInRole}.
 */
public class HasRoleFilter extends AbstractAuthorizationFilter {
  /** Name of the init parameter used to configure the expected user role. */
  public static final String ROLE = "role";

  private String role;

  public HasRoleFilter() {}

  /**
   * Constructs a filter that checks for the given role.
   *
   * <p>When this constructor is used, the {@link #ROLE} init parameter won't be read.
   */
  public HasRoleFilter(String role) {
    this.role = role;
  }

  @OverridingMethodsMustInvokeSuper
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
}
