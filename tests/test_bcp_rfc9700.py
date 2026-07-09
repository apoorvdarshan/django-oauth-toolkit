"""
Tests for the RFC 9700 (OAuth 2.0 Security Best Current Practice) gates.

Every gate is exercised in both positions: with the insecure/legacy default
(``True``) the behavior is preserved but warns, and with the compliant value
(``False``) the behavior is enforced.
"""

import hashlib
import json
from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.core import checks
from django.test import RequestFactory
from django.urls import reverse
from django.utils import timezone

from oauth2_provider.models import get_access_token_model, get_application_model
from oauth2_provider.oauth2_backends import _add_iss_to_redirect
from oauth2_provider.views import ProtectedResourceView

from .common_testing import OAuth2ProviderTestCase as TestCase
from .utils import get_basic_auth_header


Application = get_application_model()
AccessToken = get_access_token_model()
UserModel = get_user_model()

CLEARTEXT_SECRET = "1234567890abcdefghijklmnopqrstuvwxyz"


class ResourceView(ProtectedResourceView):
    def get(self, request, *args, **kwargs):
        return "This is a protected resource"


# ---------------------------------------------------------------------------
# Password (ROPC) grant gate
# ---------------------------------------------------------------------------
@pytest.mark.usefixtures("oauth2_settings")
class TestPasswordGrantGate(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = UserModel.objects.create_user("po", "po@example.com", "123456")
        cls.application = Application.objects.create(
            name="pw",
            user=cls.user,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_PASSWORD,
            client_secret=CLEARTEXT_SECRET,
        )

    def _request_token(self):
        data = {"grant_type": "password", "username": "po", "password": "123456"}
        headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)
        return self.client.post(reverse("oauth2_provider:token"), data=data, **headers)

    def test_allowed_by_default(self):
        self.assertEqual(self._request_token().status_code, 200)

    def test_rejected_when_gate_disabled(self):
        self.oauth2_settings.OAUTH_BCP_INSECURE_PASSWORD_GRANT_ENABLED = False
        response = self._request_token()
        self.assertEqual(response.status_code, 400)
        # oauthlib maps a rejected grant type to unauthorized_client.
        self.assertEqual(json.loads(response.content)["error"], "unauthorized_client")


# ---------------------------------------------------------------------------
# Implicit grant gate
# ---------------------------------------------------------------------------
@pytest.mark.usefixtures("oauth2_settings")
class TestImplicitGrantGate(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = UserModel.objects.create_user("io", "io@example.com", "123456")
        cls.application = Application.objects.create(
            name="imp",
            user=cls.user,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_IMPLICIT,
            redirect_uris="https://example.org/cb",
        )

    def _authorize(self):
        self.client.login(username="io", password="123456")
        return self.client.get(
            reverse("oauth2_provider:authorize"),
            data={
                "client_id": self.application.client_id,
                "response_type": "token",
                "redirect_uri": "https://example.org/cb",
                "scope": "read",
            },
        )

    def test_allowed_by_default(self):
        # The consent page renders (HTTP 200) when implicit is permitted.
        self.assertEqual(self._authorize().status_code, 200)

    def test_rejected_when_gate_disabled(self):
        self.oauth2_settings.OAUTH_BCP_INSECURE_IMPLICIT_GRANT_ENABLED = False
        response = self._authorize()
        # An unsupported response type is rejected rather than rendering consent.
        self.assertNotEqual(response.status_code, 200)


# ---------------------------------------------------------------------------
# PKCE "plain" method gate
# ---------------------------------------------------------------------------
@pytest.mark.usefixtures("oauth2_settings")
class TestPkcePlainGate(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = UserModel.objects.create_user("co", "co@example.com", "123456")
        cls.application = Application.objects.create(
            name="pkce",
            user=cls.user,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            redirect_uris="https://example.org/cb",
        )

    def _authorize_and_confirm(self):
        self.client.login(username="co", password="123456")
        return self.client.post(
            reverse("oauth2_provider:authorize"),
            data={
                "client_id": self.application.client_id,
                "response_type": "code",
                "redirect_uri": "https://example.org/cb",
                "scope": "read",
                "code_challenge": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "code_challenge_method": "plain",
                "state": "abc",
                "allow": True,
            },
        )

    def test_allowed_by_default(self):
        response = self._authorize_and_confirm()
        self.assertEqual(response.status_code, 302)
        self.assertIn("code=", response["Location"])

    def test_rejected_when_gate_disabled(self):
        self.oauth2_settings.OAUTH_BCP_INSECURE_PKCE_PLAIN_ENABLED = False
        response = self._authorize_and_confirm()
        # Redirect back to the client carrying an error, no authorization code.
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("code=", response["Location"])
        self.assertIn("error=", response["Location"])

    def test_iss_added_to_authorization_redirect(self):
        self.oauth2_settings.OAUTH_BCP_INSECURE_OMIT_AUTHZ_ISS_ENABLED = False
        self.client.login(username="co", password="123456")
        response = self.client.post(
            reverse("oauth2_provider:authorize"),
            data={
                "client_id": self.application.client_id,
                "response_type": "code",
                "redirect_uri": "https://example.org/cb",
                "scope": "read",
                "state": "abc",
                "allow": True,
            },
        )
        self.assertEqual(response.status_code, 302)
        # RFC 9207: the issuer (matching the metadata issuer) is echoed on the redirect.
        self.assertIn("iss=http%3A%2F%2Ftestserver%2Fo", response["Location"])

    def test_iss_omitted_by_default(self):
        self.client.login(username="co", password="123456")
        response = self.client.post(
            reverse("oauth2_provider:authorize"),
            data={
                "client_id": self.application.client_id,
                "response_type": "code",
                "redirect_uri": "https://example.org/cb",
                "scope": "read",
                "state": "abc",
                "allow": True,
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("iss=", response["Location"])


# ---------------------------------------------------------------------------
# Access token in query string gate
# ---------------------------------------------------------------------------
@pytest.mark.usefixtures("oauth2_settings")
class TestAccessTokenInQueryGate(TestCase):
    factory = RequestFactory()

    @classmethod
    def setUpTestData(cls):
        cls.user = UserModel.objects.create_user("qo", "qo@example.com", "123456")
        cls.application = Application.objects.create(
            name="q",
            user=cls.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
            client_secret=CLEARTEXT_SECRET,
        )

    def _make_token(self):
        return AccessToken.objects.create(
            user=self.user,
            token="querytoken123",
            application=self.application,
            expires=timezone.now() + timedelta(seconds=300),
            scope="read",
        )

    def test_query_token_allowed_by_default(self):
        self._make_token()
        request = self.factory.get("/fake-resource?access_token=querytoken123")
        request.user = self.user
        response = ResourceView.as_view()(request)
        self.assertEqual(response, "This is a protected resource")

    def test_query_token_rejected_when_gate_disabled(self):
        self.oauth2_settings.OAUTH_BCP_INSECURE_ACCESS_TOKEN_IN_QUERY_ENABLED = False
        self._make_token()
        request = self.factory.get("/fake-resource?access_token=querytoken123")
        request.user = self.user
        response = ResourceView.as_view()(request)
        self.assertEqual(response.status_code, 403)


# ---------------------------------------------------------------------------
# RFC 9207 iss parameter
# ---------------------------------------------------------------------------
def test_add_iss_to_redirect_query():
    result = _add_iss_to_redirect("https://c.example/cb?code=abc&state=x", "https://as.example")
    assert result == "https://c.example/cb?code=abc&state=x&iss=https%3A%2F%2Fas.example"


def test_add_iss_to_redirect_fragment():
    result = _add_iss_to_redirect("https://c.example/cb#access_token=abc", "https://as.example")
    assert result.startswith("https://c.example/cb#")
    assert "iss=https%3A%2F%2Fas.example" in result
    assert "?" not in result  # added to the fragment, not the query


@pytest.mark.usefixtures("oauth2_settings")
class TestMetadataGating(TestCase):
    def _metadata(self):
        response = self.client.get(reverse("oauth2_provider:oauth-server-metadata"))
        return json.loads(response.content)

    def test_advertises_insecure_by_default(self):
        data = self._metadata()
        self.assertIn("implicit", data["grant_types_supported"])
        self.assertIn("password", data["grant_types_supported"])
        self.assertIn("token", data["response_types_supported"])
        self.assertIn("plain", data["code_challenge_methods_supported"])
        self.assertNotIn("authorization_response_iss_parameter_supported", data)

    def test_hides_gated_behavior(self):
        self.oauth2_settings.OAUTH_BCP_INSECURE_IMPLICIT_GRANT_ENABLED = False
        self.oauth2_settings.OAUTH_BCP_INSECURE_PASSWORD_GRANT_ENABLED = False
        self.oauth2_settings.OAUTH_BCP_INSECURE_PKCE_PLAIN_ENABLED = False
        self.oauth2_settings.OAUTH_BCP_INSECURE_OMIT_AUTHZ_ISS_ENABLED = False
        data = self._metadata()
        self.assertNotIn("implicit", data["grant_types_supported"])
        self.assertNotIn("password", data["grant_types_supported"])
        self.assertNotIn("token", data["response_types_supported"])
        self.assertNotIn("plain", data["code_challenge_methods_supported"])
        self.assertTrue(data["authorization_response_iss_parameter_supported"])


# ---------------------------------------------------------------------------
# Plaintext token storage gate
# ---------------------------------------------------------------------------
@pytest.mark.usefixtures("oauth2_settings")
class TestTokenStorageGate(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = UserModel.objects.create_user("to", "to@example.com", "123456")
        cls.application = Application.objects.create(
            name="cc",
            user=cls.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
            client_secret=CLEARTEXT_SECRET,
        )

    def _get_token(self):
        data = {"grant_type": "client_credentials"}
        headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)
        response = self.client.post(reverse("oauth2_provider:token"), data=data, **headers)
        return json.loads(response.content)["access_token"]

    def test_plaintext_by_default(self):
        raw = self._get_token()
        at = AccessToken.objects.get(token_checksum=hashlib.sha256(raw.encode()).hexdigest())
        self.assertEqual(at.token, raw)

    def test_hashed_when_gate_disabled(self):
        self.oauth2_settings.OAUTH_BCP_INSECURE_PLAINTEXT_TOKEN_STORAGE_ENABLED = False
        raw = self._get_token()
        expected_checksum = hashlib.sha256(raw.encode()).hexdigest()
        at = AccessToken.objects.get(token_checksum=expected_checksum)
        # The raw token is not persisted; only its hash is stored.
        self.assertNotEqual(at.token, raw)
        self.assertEqual(at.token_checksum, expected_checksum)

    def test_hashed_token_still_authenticates(self):
        self.oauth2_settings.OAUTH_BCP_INSECURE_PLAINTEXT_TOKEN_STORAGE_ENABLED = False
        raw = self._get_token()
        request = RequestFactory().get("/fake-resource", HTTP_AUTHORIZATION="Bearer " + raw)
        request.user = self.user
        response = ResourceView.as_view()(request)
        self.assertEqual(response, "This is a protected resource")


# ---------------------------------------------------------------------------
# Deploy-time system checks
# ---------------------------------------------------------------------------
@pytest.mark.usefixtures("oauth2_settings")
class TestDeployChecks(TestCase):
    def _run(self):
        from oauth2_provider.checks import validate_bcp_configuration

        return validate_bcp_configuration(None)

    def test_warns_on_insecure_defaults(self):
        ids = {m.id for m in self._run()}
        for expected in [
            "oauth2_provider.W001",
            "oauth2_provider.W002",
            "oauth2_provider.W003",
            "oauth2_provider.W004",
            "oauth2_provider.W005",
            "oauth2_provider.W006",
            "oauth2_provider.W007",
        ]:
            self.assertIn(expected, ids)

    def test_clean_when_compliant(self):
        self.oauth2_settings.OAUTH_BCP_INSECURE_IMPLICIT_GRANT_ENABLED = False
        self.oauth2_settings.OAUTH_BCP_INSECURE_PASSWORD_GRANT_ENABLED = False
        self.oauth2_settings.OAUTH_BCP_INSECURE_PKCE_PLAIN_ENABLED = False
        self.oauth2_settings.OAUTH_BCP_INSECURE_ACCESS_TOKEN_IN_QUERY_ENABLED = False
        self.oauth2_settings.OAUTH_BCP_INSECURE_OMIT_AUTHZ_ISS_ENABLED = False
        self.oauth2_settings.OAUTH_BCP_INSECURE_PLAINTEXT_TOKEN_STORAGE_ENABLED = False
        self.oauth2_settings.REFRESH_TOKEN_REUSE_PROTECTION = True
        self.oauth2_settings.ALLOWED_REDIRECT_URI_SCHEMES = ["https"]
        self.assertEqual(self._run(), [])

    def test_error_on_hashed_storage_with_grace_period(self):
        self.oauth2_settings.OAUTH_BCP_INSECURE_PLAINTEXT_TOKEN_STORAGE_ENABLED = False
        self.oauth2_settings.REFRESH_TOKEN_GRACE_PERIOD_SECONDS = 60
        errors = [m for m in self._run() if isinstance(m, checks.Error)]
        self.assertEqual([m.id for m in errors], ["oauth2_provider.E001"])
