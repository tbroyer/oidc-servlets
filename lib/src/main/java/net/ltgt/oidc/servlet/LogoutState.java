package net.ltgt.oidc.servlet;

import com.nimbusds.oauth2.sdk.id.State;

record LogoutState(
    State state, //
    String requestUri //
    ) {
  static final String SESSION_ATTRIBUTE_NAME = LogoutState.class.getName();
}
