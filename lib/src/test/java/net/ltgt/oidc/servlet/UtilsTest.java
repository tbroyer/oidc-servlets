package net.ltgt.oidc.servlet;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import org.junit.jupiter.api.Test;

class UtilsTest {

  @Test
  void resolveMtlsEndpointAliases() throws Exception {
    // This is Figure 4 from RFC 8705; https://datatracker.ietf.org/doc/html/rfc8705
    // with the addition of OIDC-required subject_types_supported field
    var original =
        OIDCProviderMetadata.parse(
            """
            {
              "issuer": "https://server.example.com",
              "authorization_endpoint": "https://server.example.com/authz",
              "token_endpoint": "https://server.example.com/token",
              "introspection_endpoint": "https://server.example.com/introspect",
              "revocation_endpoint": "https://server.example.com/revo",
              "jwks_uri": "https://server.example.com/jwks",
              "response_types_supported": ["code"],
              "response_modes_supported": ["fragment","query","form_post"],
              "grant_types_supported": ["authorization_code", "refresh_token"],
              "token_endpoint_auth_methods_supported":
                              ["tls_client_auth","client_secret_basic","none"],
              "tls_client_certificate_bound_access_tokens": true,
              "mtls_endpoint_aliases": {
                "token_endpoint": "https://mtls.example.com/token",
                "revocation_endpoint": "https://mtls.example.com/revo",
                "introspection_endpoint": "https://mtls.example.com/introspect"
              },
              "subject_types_supported": ["public"]
            }
            """);
    var expected =
        OIDCProviderMetadata.parse(
            """
            {
              "issuer": "https://server.example.com",
              "authorization_endpoint": "https://server.example.com/authz",
              "token_endpoint": "https://mtls.example.com/token",
              "introspection_endpoint": "https://mtls.example.com/introspect",
              "revocation_endpoint": "https://mtls.example.com/revo",
              "jwks_uri": "https://server.example.com/jwks",
              "response_types_supported": ["code"],
              "response_modes_supported": ["fragment","query","form_post"],
              "grant_types_supported": ["authorization_code", "refresh_token"],
              "token_endpoint_auth_methods_supported":
                              ["tls_client_auth","client_secret_basic","none"],
              "tls_client_certificate_bound_access_tokens": true,
              "subject_types_supported": ["public"]
            }
            """);

    var actual = Utils.resolveMtlsEndpointAliases(original);

    assertThat(actual.toJSONObject()).isEqualTo(expected.toJSONObject());
  }
}
