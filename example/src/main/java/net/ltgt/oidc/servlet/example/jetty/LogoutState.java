package net.ltgt.oidc.servlet.example.jetty;

import com.nimbusds.oauth2.sdk.id.State;

public record LogoutState(
    State state, //
    String requestUri //
    ) {
  static final String SESSION_ATTRIBUTE_NAME = LogoutState.class.getName();
}
