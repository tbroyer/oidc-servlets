package net.ltgt.oidc.servlet;

import static com.google.common.truth.Truth.assertThat;

import com.google.common.testing.SerializableTester;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import java.sql.Date;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import org.junit.jupiter.api.Test;

public class SerializabilityTest {
  @Test
  void testSessionInfo() throws Exception {
    var idTokenClaims =
        new IDTokenClaimsSet(
            new Issuer("issuer"),
            new Subject("sub"),
            List.of(new Audience("audience")),
            Date.from(Instant.now().plus(10, ChronoUnit.MINUTES)),
            Date.from(Instant.now().minus(5, ChronoUnit.MINUTES)));
    var idToken = new PlainJWT(idTokenClaims.toJWTClaimsSet());
    var initial = new SessionInfo(idToken, idTokenClaims, new UserInfo(new Subject("sub")));
    var copy = SerializableTester.reserialize(initial);
    // assertThat(copy).isEqualTo(initial);
    assertThat(copy.getIDToken().serialize()).isEqualTo(initial.getIDToken().serialize());
    //    assertThat(copy.getIDTokenClaims()).isEqualTo(initial.getIDTokenClaims());
    assertThat(copy.getUserInfo()).isEqualTo(initial.getUserInfo());
  }

  @Test
  void testAuthenticationState() {
    SerializableTester.reserializeAndAssert(
        new AuthenticationState(new State(), new Nonce(), new CodeVerifier(), "/"));
  }

  @Test
  void testLogoutState() {
    SerializableTester.reserializeAndAssert(new LogoutState(new State(), "/"));
  }
}
