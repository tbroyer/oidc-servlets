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
package net.ltgt.oidc.servlet.rs;

import com.google.common.testing.NullPointerTester;
import com.google.common.testing.NullPointerTester.Visibility;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import java.lang.reflect.Modifier;
import java.net.URI;
import java.util.List;
import net.ltgt.oidc.servlet.AuthenticationRedirector;
import net.ltgt.oidc.servlet.Configuration;
import net.ltgt.oidc.servlet.HasRoleFilter;
import net.ltgt.oidc.servlet.IsAuthenticatedFilter;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

public class NullSafetyTest {
  private <T> void testPublicApi(NullPointerTester tester, Class<T> cls, @Nullable T instance) {
    tester.testStaticMethods(cls, Visibility.PROTECTED);
    if (!Modifier.isAbstract(cls.getModifiers())) {
      tester.testConstructors(cls, Visibility.PROTECTED);
    }
    if (instance != null) {
      tester.testInstanceMethods(instance, Visibility.PROTECTED);
    }
  }

  @Test
  void testFilters() {
    var oidcProviderMetadata =
        new OIDCProviderMetadata(
            new Issuer("issuer"),
            List.of(SubjectType.PUBLIC),
            URI.create("https://example.com/jwks"));
    var clientAuthentication = new ClientSecretBasic(new ClientID(), new Secret());
    var configuration = new Configuration(oidcProviderMetadata, clientAuthentication);
    var tester =
        new NullPointerTester()
            .setDefault(
                AuthenticationRedirector.class,
                new AuthenticationRedirector(configuration, "/callback"));
    testPublicApi(tester, AbstractAuthorizationFilter.class, null);
    testPublicApi(tester, IsAuthenticatedFilter.class, null);
    testPublicApi(tester, HasRoleFeature.class, null);
    testPublicApi(tester, HasRoleFilter.class, null);
  }

  @Test
  void testUtils() {
    var oidcProviderMetadata =
        new OIDCProviderMetadata(
            new Issuer("issuer"),
            List.of(SubjectType.PUBLIC),
            URI.create("https://example.com/jwks"));
    var clientAuthentication = new ClientSecretBasic(new ClientID(), new Secret());
    var configuration = new Configuration(oidcProviderMetadata, clientAuthentication);
    var tester =
        new NullPointerTester()
            .setDefault(
                AuthenticationRedirector.class,
                new AuthenticationRedirector(configuration, "/callback"));
    testPublicApi(tester, Utils.class, null);
  }
}
