package net.ltgt.oidc.servlet;

import static java.util.Objects.requireNonNull;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import java.io.Serial;
import java.io.Serializable;

public final class SessionInfo implements Serializable {
  static final String SESSION_ATTRIBUTE_NAME = SessionInfo.class.getName();

  private final OIDCTokens oidcTokens;
  private final IDTokenClaimsSet idTokenClaims;
  private final UserInfo userInfo;

  public SessionInfo(
      OIDCTokens oidcTokens, //
      IDTokenClaimsSet idTokenClaims,
      UserInfo userInfo //
      ) {
    this.oidcTokens = requireNonNull(oidcTokens);
    this.idTokenClaims = requireNonNull(idTokenClaims);
    this.userInfo = requireNonNull(userInfo);
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

  @Serial
  private Object writeReplace() {
    return new SerializableSessionInfo(
        oidcTokens.toJSONObject().toJSONString(), userInfo.toJSONString());
  }

  private record SerializableSessionInfo(String serializedOidcTokens, String serializedUserInfo)
      implements Serializable {
    @Serial
    Object readResolve() {
      try {
        var oidcTokens = OIDCTokens.parse(JSONObjectUtils.parse(serializedOidcTokens()));
        var userInfo = UserInfo.parse(serializedUserInfo());
        return new SessionInfo(
            oidcTokens, new IDTokenClaimsSet(oidcTokens.getIDToken().getJWTClaimsSet()), userInfo);
      } catch (ParseException | java.text.ParseException e) {
        throw new RuntimeException(e);
      }
    }
  }
}
