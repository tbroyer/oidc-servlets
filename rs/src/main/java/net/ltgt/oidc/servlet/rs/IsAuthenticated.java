package net.ltgt.oidc.servlet.rs;

import jakarta.ws.rs.NameBinding;
import jakarta.ws.rs.core.SecurityContext;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Ensures the user {@linkplain SecurityContext#getUserPrincipal is authenticated}, by creating a
 * named binding with {@link IsAuthenticatedFilter}.
 *
 * @see IsAuthenticatedFilter
 */
@Documented
@NameBinding
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
public @interface IsAuthenticated {}
