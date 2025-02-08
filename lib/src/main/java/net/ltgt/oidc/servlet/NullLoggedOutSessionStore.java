package net.ltgt.oidc.servlet;

import com.nimbusds.openid.connect.sdk.claims.SessionID;

class NullLoggedOutSessionStore implements LoggedOutSessionStore {
  public static final LoggedOutSessionStore INSTANCE = new NullLoggedOutSessionStore();

  private NullLoggedOutSessionStore() {}

  @Override
  public void logout(SessionID sessionID) {}
}
