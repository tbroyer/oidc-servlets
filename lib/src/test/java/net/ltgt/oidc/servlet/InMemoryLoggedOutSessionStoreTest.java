package net.ltgt.oidc.servlet;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.openid.connect.sdk.claims.SessionID;
import org.junit.jupiter.api.Test;

class InMemoryLoggedOutSessionStoreTest {
  @Test
  public void loginThenLogout() {
    var sut = new InMemoryLoggedOutSessionStore();

    assertThat(sut.isLoggedOut(new SessionID("sid"))).isTrue();

    sut.acquire(new SessionID("sid"), "1");
    assertThat(sut.isLoggedOut(new SessionID("sid"))).isFalse();

    sut.release(new SessionID("sid"), "1");
    assertThat(sut.isLoggedOut(new SessionID("sid"))).isTrue();
  }

  @Test
  public void loginRenewThenLogout() {
    var sut = new InMemoryLoggedOutSessionStore();

    assertThat(sut.isLoggedOut(new SessionID("sid"))).isTrue();

    sut.acquire(new SessionID("sid"), "1");
    assertThat(sut.isLoggedOut(new SessionID("sid"))).isFalse();

    sut.renew(new SessionID("sid"), "1", "2");
    assertThat(sut.isLoggedOut(new SessionID("sid"))).isFalse();

    sut.release(new SessionID("sid"), "2");
    assertThat(sut.isLoggedOut(new SessionID("sid"))).isTrue();
  }

  @Test
  public void twoParallelSessions() {
    var sut = new InMemoryLoggedOutSessionStore();

    assertThat(sut.isLoggedOut(new SessionID("sid"))).isTrue();

    sut.acquire(new SessionID("sid"), "1");
    assertThat(sut.isLoggedOut(new SessionID("sid"))).isFalse();

    sut.acquire(new SessionID("sid"), "2");
    assertThat(sut.isLoggedOut(new SessionID("sid"))).isFalse();

    sut.release(new SessionID("sid"), "1");
    assertThat(sut.isLoggedOut(new SessionID("sid"))).isFalse();

    sut.release(new SessionID("sid"), "2");
    assertThat(sut.isLoggedOut(new SessionID("sid"))).isTrue();
  }

  @Test
  public void loginThenBackChannelLogout() {
    var sut = new InMemoryLoggedOutSessionStore();

    assertThat(sut.isLoggedOut(new SessionID("sid"))).isTrue();

    sut.acquire(new SessionID("sid"), "1");
    assertThat(sut.isLoggedOut(new SessionID("sid"))).isFalse();

    sut.logout(new SessionID("sid"));
    assertThat(sut.isLoggedOut(new SessionID("sid"))).isTrue();

    // Would be called by BackchannelLogoutSessionListener, shouldn't fail or have side-effects
    sut.release(new SessionID("sid"), "1");
    assertThat(sut.isLoggedOut(new SessionID("sid"))).isTrue();
  }

  @Test
  public void noSessionInterference() {
    var sut = new InMemoryLoggedOutSessionStore();

    assertThat(sut.isLoggedOut(new SessionID("a"))).isTrue();
    assertThat(sut.isLoggedOut(new SessionID("b"))).isTrue();

    sut.acquire(new SessionID("a"), "1");
    sut.acquire(new SessionID("b"), "2");
    assertThat(sut.isLoggedOut(new SessionID("a"))).isFalse();
    assertThat(sut.isLoggedOut(new SessionID("b"))).isFalse();

    sut.release(new SessionID("b"), "2");
    assertThat(sut.isLoggedOut(new SessionID("a"))).isFalse();
    assertThat(sut.isLoggedOut(new SessionID("b"))).isTrue();

    sut.release(new SessionID("a"), "1");
    assertThat(sut.isLoggedOut(new SessionID("a"))).isTrue();
    assertThat(sut.isLoggedOut(new SessionID("b"))).isTrue();
  }

  @Test
  public void noSessionInterference_backChannelLogout() {
    var sut = new InMemoryLoggedOutSessionStore();

    assertThat(sut.isLoggedOut(new SessionID("a"))).isTrue();
    assertThat(sut.isLoggedOut(new SessionID("b"))).isTrue();

    sut.acquire(new SessionID("a"), "1");
    sut.acquire(new SessionID("b"), "2");
    assertThat(sut.isLoggedOut(new SessionID("a"))).isFalse();
    assertThat(sut.isLoggedOut(new SessionID("b"))).isFalse();

    sut.logout(new SessionID("b"));
    assertThat(sut.isLoggedOut(new SessionID("a"))).isFalse();
    assertThat(sut.isLoggedOut(new SessionID("b"))).isTrue();

    sut.logout(new SessionID("a"));
    assertThat(sut.isLoggedOut(new SessionID("a"))).isTrue();
    assertThat(sut.isLoggedOut(new SessionID("b"))).isTrue();
  }

  @Test
  public void logoutWithoutLogin() {
    var sut = new InMemoryLoggedOutSessionStore();

    assertThat(sut.isLoggedOut(new SessionID("sid"))).isTrue();

    sut.release(new SessionID("sid"), "1");
    assertThat(sut.isLoggedOut(new SessionID("sid"))).isTrue();
  }

  @Test
  public void logoutWithoutLogin_existingSessionID() {
    var sut = new InMemoryLoggedOutSessionStore();

    assertThat(sut.isLoggedOut(new SessionID("sid"))).isTrue();

    sut.acquire(new SessionID("sid"), "1");
    assertThat(sut.isLoggedOut(new SessionID("sid"))).isFalse();

    sut.release(new SessionID("sid"), "unexpected");
    assertThat(sut.isLoggedOut(new SessionID("sid"))).isFalse();

    sut.release(new SessionID("sid"), "1");
    assertThat(sut.isLoggedOut(new SessionID("sid"))).isTrue();
  }

  @Test
  public void backchannelLogoutWithoutLogin() {
    var sut = new InMemoryLoggedOutSessionStore();

    assertThat(sut.isLoggedOut(new SessionID("sid"))).isTrue();

    sut.logout(new SessionID("sid"));
    assertThat(sut.isLoggedOut(new SessionID("sid"))).isTrue();
  }
}
