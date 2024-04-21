package net.ltgt.oidc.servlet;

import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.Nonce;

record AuthenticationState(
    State state, //
    Nonce nonce,
    CodeVerifier codeVerifier,
    String requestUri //
    ) {
  static final String SESSION_ATTRIBUTE_NAME = AuthenticationState.class.getName();
}
