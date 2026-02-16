/*
 * Copyright © 2026 Thomas Broyer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
