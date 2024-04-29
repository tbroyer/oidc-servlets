# oidc-servlets

OIDC-Servlets is a library of servlets and filters using the [Nimbus OIDC SDK](https://connect2id.com/products/nimbus-oauth-openid-connect-sdk) to implement an OpenID Connect relying-party.

## Rationale

For a few years I've been using [Pac4j](https://www.pac4j.org) to secure web apps with [OpenID Connect](https://openid.net/connect/), but as requirements differ slightly between applications, I've found Pac4j's complexity to be overwhelming given my relatively simple needs.
Pac4j is a very well-thought-out authentication framework that allows handling many cases, and it's a great fit for, for example but not limited to, products that can be deployed in various environments, but that comes at a cost of complexity.
My needs are rather simple, so I want something simpler, and it turns out Nimbus (that powers Pac4j's OpenID Connect support) is relatively easy to use on its own, so that's what I'm doing here.

## Requirements

The project requires a JDK in version 21 or higher, and Docker with Docker Compose.

It fulfills the following needs:

* A public (authentication-aware, but not requiring authentication) homepage
* A private (requiring authentication) page, accessible to any registered user
* A private (requiring authentication) admin page, only accessible to administrator users
* A single API servlet that can tell users apart and handle authorizations (depending on projects this could be Jakarta RS or GraphQL for example)
* Static resources don't necessarily need authentication (more precisely, subresources –whether static or not, though most likely they are– should not redirect for authentication but rather either be served anyway or just blocked, both behaviors should be possible depending on needs)
* Authentication should work well with internal servlet forwarding, as that's how I serve the same HTML web page for various URLs for Single Page Applications (SPA) that are fully client-side rendered (CSR); more precisely, the URL to redirect to after authentication should be the originally requested URL and not the one the request has been forwarded to.

## Example application

First, start a [Keycloak](https://www.keycloak.org) server with an example configuration with Docker Compose:

```
docker compose up -d
```

This will start Keycloak, then configure a realm, a client, and a couple users, using [keycloak-config-cli](https://github.com/adorsys/keycloak-config-cli).
The server listens on http://localhost:8080/, the Keycloak administrator is `kcadmin`/`kcadmin`, and test users in the `example` realm are `admin`/`admin` and `user`/`user`.

Then start the example application (preconfigured to integrate with that Keycloak server and configuration):

```
./gradlew run
```

This will compile the code then execute it. Hit <kbd>Ctrl</kbd>+<kbd>C</kbd> to terminate the process.
The server listens on http://localhost:8000/.

## Usage

Create `Configuration` and `AuthenticatorRedirector` objects and add them as `ServletContext` attributes (the attribute names are in the `CONTEXT_ATTRIBUTE_NAME` static constants of each class):

```java
var configuration = new Configuration(/* … */);
var redirector = new AuthenticationRedirector(configuration, CALLBACK_PATH);

servletContext.setAttribute(Configuration.CONTEXT_ATTRIBUTE_NAME, configuration);
servletContext.setAttribute(AuthenticationRedirector.CONTEXT_ATTRIBUTE_NAME, redirector);
```

Register the `CallbackServlet` to the path configured with the `AuthenticationRedirector`:

```java
// Using the ServletContext dynamic registration (e.g. from ServletContextInitializer)
servletContext.addServlet("oidc-callback", CallbackServlet.class)
    .addMapping(CALLBACK_PATH);
// Using Jetty's ServletContextHandler
servletContextHandler.addServlet(CallbackServlet.class, CALLBACK_PATH);
// Using Undertow
Servlets.servlet(CallbackServlet.class).addMapping(CALLBACK_PATH);
```

To determine if the user is logged in, register the `UserFilter`, most likely to all requests, and it should match early; this filter will set up the `HttpServletRequest` for later filters and servlets to answer the `getRemoteUser()`, `getUserPrincipal()`, and `isUserInRole(String)` methods:
```java
// Using the ServletContext dynamic registration (e.g. from ServletContextInitializer)
servletContext.addFilter("user", UserFilter.class)
    .addMappingForUrlPatterns(null, false, "/*");
```

The implementation of `isUserInRole(String)` relies on the actual `UserPrincipal`, which is derived from the ID Token and User Info. The default implementation (`SimpleUserPrincipal`) always returns `false` (the user has no known role). Another implementation (`KeycloakUserPrincipal`) reads Keycloak realm roles from the User Info, and can be configured by passing the class' constructor to the `Configuration` constructor:

```java
var configuration = new Configuration(
    providerMetadata, clientAuthentication, KeycloakUserPrincipal::new);
```

Custom `UserPrincipal` implementations can be created for other OpenID Providers.

### Login

Now, to redirect to the OpenID Provider, register one or many _authorization filters_, depending on needs. The `IsAuthenticatedFilter` requires an authenticated user; it's more or less equivalent to the `<role-name>*</role-name>` security constraint of standard servlet security (when authentication is delegated to the servlet container). The `HasRoleFilter` requires that the user has a given role, that needs to be configured with the `role` init parameter, or passed to the filter constructor; it's more or less equivalent to a `<role-name>` security constraint (though only supporting one role). Other needs can be fulfilled by subclassing `AbstractAuthorizationFilter`. Those filters rely on the user _detected_ by the `UserFilter`, so beware of filter ordering.

For example, for an application that requires authentication everywhere:

```java
// Using the ServletContext dynamic registration (e.g. from ServletContextInitializer)
servletContext.addFilter("authenticated-user", IsAuthenticatedFilter.class)
    .addMappingForUrlPatterns(null, true, "/*");
```

or for an application with public and private sections:

```java
// Using the ServletContext dynamic registration (e.g. from ServletContextInitializer)
servletContext.addFilter("authenticated-user", IsAuthenticatedFilter.class)
    .addMappingForUrlPatterns(null, true, "/private/*");
```

To allow users on public pages to sign in, you can register the `LoginServlet`, and add to those pages either a link to that servlet, or an HTML form to do a `POST` request to that servlet, including the URL to return to after authentication in a `return-to` query-string or form parameter (if omitted, the user will be redirected to the root of the application, same as `return-to=/`):

```java
// Using the ServletContext dynamic registration (e.g. from ServletContextInitializer)
servletContext.addServlet("login", LoginServlet.class)
    .addMapping("/login");
```

The target page should be given as an absolute path (possibly with a query string), though a full URL would be accepted as long as it's the same [origin](https://datatracker.ietf.org/doc/html/rfc6454). You can use `Utils.getRequestUri(request)` to easily get the path and query string of the current request (taking into account internal servlet forwarding to return the information of the original request). Here's an example in a JSP:
```html
<!-- Using a link -->
<a href='/login?<c:out value="${Utils.RETURN_TO_PARAMETER_NAME}" />=<c:out value="${Utils.getRequestUri(request)}" />'>Sign in</a>

<!-- Using a form -->
<form method="post" action="/login">
  <input type="hidden" name='<c:out value="${Utils.RETURN_TO_PARAMETER_NAME}" />'
         value='<c:out value="${Utils.getRequestUri(request)}" />'>
  <button type="submit">Sign in</button>
</form>
```

<!-- TODO: configurable scope, usage of access token and refresh token -->

### Logout

To allow users to sign out, register the `LogoutServlet` and add an HTML form to the application to do a `POST` request to that servlet. By default, no `post_logout_redirect_uri` is being used, so most likely the OpenID Provider will display a page to the user confirming their logout, and possibly including a link back to the application.

```java
// Using the ServletContext dynamic registration (e.g. from ServletContextInitializer)
servletContext.addServlet("logout", LogoutServlet.class)
    .addMapping("/logout");
```

To use a `post_logout_redirect_uri`, configure its path with the `post-logout-redirect-path` init parameter (or passing the value to the servlet constructor); this should be a _public_ page, otherwise the user will directly be sent back to the OpenID Provider for signing in again, and it should be properly registered at the OpenID Provider:

```java
// Using the ServletContext dynamic registration (e.g. from ServletContextInitializer)
servletContext.addServlet("logout", new LogoutServlet("/"))
    .addMapping("/logout");
```

To allow the redirection target to be dynamically chosen (e.g. to return to the public page the user signed out from):

* register the `LogoutCallbackServlet` in addition to the `LogoutServlet`:

  ```java
  // Using the ServletContext dynamic registration (e.g. from ServletContextInitializer)
  servletContext.addServlet("logout-callback", LogoutCallbackServlet.class)
      .addMapping(LOGOUT_CALLBACK_PATH);
  ```

* configure the `use-logout-state` init parameter to `true` (or pass `true` as the second argument to the servlet constructor), and configure the `post-logout-redirect-path` to the path of the `LogoutCallbackServlet` (which should be properly registered on the OpenID Provider):

  ```java
  // Using the ServletContext dynamic registration (e.g. from ServletContextInitializer)
  servletContext.addServlet("logout", new LogoutServlet(LOGOUT_CALLBACK_PATH, true))
      .addMapping("/logout");
  ```

* pass the target page as a `return-to` form parameter (make sure it's a public page to avoid immediately redirecting back to the OpenID Provider for authentication); the target page should be given as an absolute path (possibly with a query string), though a full URL would be accepted as long as its the same [origin](https://datatracker.ietf.org/doc/html/rfc6454); you can use `Utils.getRequestUri(request)` to easily get the path and query string of the current request (taking into account internal servlet forwarding to return the information of the original request). Here's an example in a JSP:

  ```html
  <form method="post" action="/logout">
    <input type="hidden" name="<c:out value="${Utils.RETURN_TO_PARAMETER_NAME}" />"
           value="<c:out value="${Utils.getRequestUri(request)}" />">
    <button type="submit">Sign out</button>
  </form>
  ```

### Single sign-out (back-channel logout)

To use [OpenID Connect Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html), you need a way to invalidate sessions based on an identifier managed by the OpenID Provider (the `sid`). This can be accomplished by storing the identifiers of the logged-out sessions and then matching them whenever a request comes in to invalidate them on a case-by-case basis (this means the sessions are only effectively terminated the next time they're used, and not immediately). This is implemented here with the `LoggedOutSessionStore` that will be used by the `UserFilter` when one is added as a `ServletContext` attribute, and the `BackchannelLogoutSessionListener` will remove effectively invalidated identifiers from the `LoggedOutSessionStore`. Finally, the `BackchannelLogoutServlet`, whose URL has to be properly registered on the OpenID Provider, will receive the logout requests from the OpenID Provider and put the identifiers into the `LoggedOutSessionStore` after validating the request. This requires that the OpenID Provider sends a `sid` in the ID Token at authentication time, and in the Logout Token sent to the `BackchannelLogoutServlet` (i.e. the provider metadata has `"backchannel_logout_session_supported": true`, and the client registration would have `"backchannel_logout_session_required": true`).

```java
// Using the ServletContext dynamic registration (e.g. from ServletContextInitializer)
servletContext.setAttribute(
    LoggedOutSessionStore.CONTEXT_ATTRIBUTE_NAME, new InMemoryLoggedOutSessionStore());
servletContext.addListener(new BackchannelLogoutSessionListener());
servletContext.addServlet("backchannel-logout", BackchannelLogoutServlet.class)
    .addMapping("/backchannel-logout");
```

<!-- TODO: allow specific implementations to immediately invalidate sessions -->
