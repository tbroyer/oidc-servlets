package net.ltgt.oidc.servlet.example.jetty;

import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;

public record SessionInfo(
    OIDCTokens oidcTokens, //
    IDTokenClaimsSet idTokenClaims,
    UserInfo userInfo //
    ) {
  static final String SESSION_ATTRIBUTE_NAME = SessionInfo.class.getName();
}
