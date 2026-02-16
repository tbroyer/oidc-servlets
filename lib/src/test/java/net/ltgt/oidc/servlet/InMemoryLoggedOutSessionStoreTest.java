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
