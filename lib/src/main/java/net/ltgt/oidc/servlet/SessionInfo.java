package net.ltgt.oidc.servlet;

import static java.util.Objects.requireNonNull;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import java.io.Serial;
import java.io.Serializable;

public final class SessionInfo implements Serializable {
  static final String SESSION_ATTRIBUTE_NAME = SessionInfo.class.getName();

  private final JWT idToken;
  private final IDTokenClaimsSet idTokenClaims;
  private final UserInfo userInfo;

  public SessionInfo(
      JWT idToken, //
      IDTokenClaimsSet idTokenClaims, //
      UserInfo userInfo //
      ) {
    this.idToken = idToken;
    this.idTokenClaims = requireNonNull(idTokenClaims);
    this.userInfo = requireNonNull(userInfo);
  }

  public JWT getIDToken() {
    return idToken;
  }

  public IDTokenClaimsSet getIDTokenClaims() {
    return idTokenClaims;
  }

  public UserInfo getUserInfo() {
    return userInfo;
  }

  @Serial
  private Object writeReplace() {
    return new SerializableSessionInfo(idToken.serialize(), userInfo.toJSONString());
  }

  private record SerializableSessionInfo(String idToken, String serializedUserInfo)
      implements Serializable {
    @Serial
    Object readResolve() {
      try {
        var parsedIdToken = JWTParser.parse(idToken());
        var idTokenClaims = new IDTokenClaimsSet(parsedIdToken.getJWTClaimsSet());
        var userInfo = UserInfo.parse(serializedUserInfo());
        return new SessionInfo(parsedIdToken, idTokenClaims, userInfo);
      } catch (ParseException | java.text.ParseException e) {
        throw new RuntimeException(e);
      }
    }
  }
}
