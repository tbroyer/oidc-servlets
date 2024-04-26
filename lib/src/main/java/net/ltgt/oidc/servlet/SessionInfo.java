package net.ltgt.oidc.servlet;

import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;

public final class SessionInfo {
  static final String SESSION_ATTRIBUTE_NAME = SessionInfo.class.getName();

  private final OIDCTokens oidcTokens;
  private final IDTokenClaimsSet idTokenClaims;
  private final UserInfo userInfo;

  public SessionInfo(
      OIDCTokens oidcTokens, //
      IDTokenClaimsSet idTokenClaims,
      UserInfo userInfo //
      ) {
    this.oidcTokens = oidcTokens;
    this.idTokenClaims = idTokenClaims;
    this.userInfo = userInfo;
  }

  public OIDCTokens getOIDCTokens() {
    return oidcTokens;
  }

  public IDTokenClaimsSet getIDTokenClaims() {
    return idTokenClaims;
  }

  public UserInfo getUserInfo() {
    return userInfo;
  }
}
