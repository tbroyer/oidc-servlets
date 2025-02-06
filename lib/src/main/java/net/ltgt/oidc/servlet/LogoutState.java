package net.ltgt.oidc.servlet;

import com.nimbusds.oauth2.sdk.id.State;
import java.io.Serializable;

record LogoutState(
    State state, //
    String requestUri //
    ) implements Serializable {
  static final String SESSION_ATTRIBUTE_NAME = LogoutState.class.getName();
}
