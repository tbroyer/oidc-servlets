# oidc-servlets-rs

OIDC-Servlets+RS is a companion library to [OIDC-Servlets](../README.md) providing JAX-RS filters to manage authorizations on JAX-RS resources (in a servlets environment).

## Usage

Add dependencies on [`net.ltgt.oidc:oidc-servlets`](https://central.sonatype.com/artifact/net.ltgt.oidc/oidc-servlets) and [`net.ltgt.oidc:oidc-servlets-rs`](https://central.sonatype.com/artifact/net.ltgt.oidc/oidc-servlets-rs). You can also use the [`net.ltgt.oidc:oidc-servlets-bom`](https://central.sonatype.com/artifact/net.ltgt.oidc/oidc-servlets-bom) BOM to align those dependencies on the same version.
You should also add dependencies on [`com.nimbusds:oauth2-oidc-sdk`](https://central.sonatype.com/artifact/com.nimbusds/oauth2-oidc-sdk) and [`com.nimbusds:nimbus-jose-jwt`](https://central.sonatype.com/artifact/com.nimbusds/nimbus-jose-jwt) so you can keep them up-to-date independently of OIDC-Servlets+RS.

Configure the `UserFilter` and `CallbackServlet` from [OIDC-Servlets](../README.md#usage). You can also use the other servlets from OIDC-Servlets: `LoginServlet`, `LogoutServlet`, `LogoutCallbackServlet`, and `BackchannelLogoutServlet`.

You can then use the `IsAuthenticatedFilter` and `HasRoleFilter` JAX-RS filters.

The `IsAuthenticatedFilter` requires an authenticated user. Annotating your resource method, resource class, or application class with `@IsAuthenticated` to bind this filter to your resources.

The `HasRoleFilter` requires that the user has a given role; this requires using a custom `UserPrincipal` (if only a `KeycloakUserPrincipal`). Register the `HasRoleFeature` and annotate your resource method or resource class with `@HasRole()` to bind the filter to your resources. You can also create subclasses with a name binding; make sure to register them with a priority higher than `Priorities.AUTHENTICATION` (most likely `Priorities.AUTHORIZATION`).

Other needs can be fulfilled by subclassing `AbstractAuthorizationFilter`.
