from django.apps import apps
from django.core import checks
from django.db import router

from .settings import oauth2_settings


# RFC 9700 (OAuth 2.0 Security Best Current Practice) gates. Each tuple is
# (setting name, short description of the insecure behavior, check id). The default
# for every gate keeps the insecure/legacy behavior and is scheduled to flip in 4.0.
_BCP_GATES = [
    (
        "OAUTH_BCP_INSECURE_IMPLICIT_GRANT_ENABLED",
        "the OAuth 2.0 implicit grant is enabled (RFC 9700 §2.1.2)",
        "oauth2_provider.W001",
    ),
    (
        "OAUTH_BCP_INSECURE_PASSWORD_GRANT_ENABLED",
        "the resource owner password credentials grant is enabled (RFC 9700 §2.4)",
        "oauth2_provider.W002",
    ),
    (
        "OAUTH_BCP_INSECURE_PKCE_PLAIN_ENABLED",
        'the PKCE "plain" code_challenge_method is accepted (RFC 9700 §2.1.1)',
        "oauth2_provider.W003",
    ),
    (
        "OAUTH_BCP_INSECURE_ACCESS_TOKEN_IN_QUERY_ENABLED",
        "access tokens are accepted in the URI query string (RFC 9700 §4.3.2)",
        "oauth2_provider.W004",
    ),
    (
        "OAUTH_BCP_INSECURE_OMIT_AUTHZ_ISS_ENABLED",
        "the RFC 9207 `iss` authorization-response parameter is omitted (RFC 9700 §4.4)",
        "oauth2_provider.W005",
    ),
    (
        "OAUTH_BCP_INSECURE_PLAINTEXT_TOKEN_STORAGE_ENABLED",
        "access and refresh tokens are stored in plaintext (RFC 9700 §4)",
        "oauth2_provider.W006",
    ),
]


@checks.register(checks.Tags.security, deploy=True)
def validate_bcp_configuration(app_configs, **kwargs):
    """
    Warn about configuration that does not follow RFC 9700 (only under ``--deploy``).

    These are warnings, not errors: the insecure defaults are intentional for backward
    compatibility and are scheduled to flip to the compliant value in the 4.0 release.
    """
    messages = []
    for setting_name, behavior, check_id in _BCP_GATES:
        if getattr(oauth2_settings, setting_name):
            messages.append(
                checks.Warning(
                    f"RFC 9700 (OAuth 2.0 Security BCP): {behavior}.",
                    hint=(
                        f"Set OAUTH2_PROVIDER['{setting_name}'] = False to adopt the "
                        "compliant behavior. This default is scheduled to change in 4.0."
                    ),
                    id=check_id,
                )
            )

    if not oauth2_settings.REFRESH_TOKEN_REUSE_PROTECTION:
        messages.append(
            checks.Warning(
                "RFC 9700 (OAuth 2.0 Security BCP): refresh token replay detection is disabled (§4.14.2).",
                hint=(
                    "Set OAUTH2_PROVIDER['REFRESH_TOKEN_REUSE_PROTECTION'] = True to revoke "
                    "the whole token family when a refresh token is replayed."
                ),
                id="oauth2_provider.W007",
            )
        )

    if "http" in oauth2_settings.ALLOWED_REDIRECT_URI_SCHEMES:
        messages.append(
            checks.Warning(
                "RFC 9700 (OAuth 2.0 Security BCP): plaintext `http` redirect URIs are allowed (§2.1).",
                hint=(
                    "Remove 'http' from OAUTH2_PROVIDER['ALLOWED_REDIRECT_URI_SCHEMES'] to "
                    "require https redirect URIs. Note this also disallows native-app "
                    "loopback (http://127.0.0.1) callbacks per RFC 8252, so keep 'http' if "
                    "you must support them."
                ),
                id="oauth2_provider.W008",
            )
        )

    # Redacting tokens at rest is incompatible with the refresh-token grace period,
    # which must return the previously issued (plaintext) token from the database.
    if (
        not oauth2_settings.OAUTH_BCP_INSECURE_PLAINTEXT_TOKEN_STORAGE_ENABLED
        and oauth2_settings.REFRESH_TOKEN_GRACE_PERIOD_SECONDS > 0
    ):
        messages.append(
            checks.Error(
                "Hashed token storage (OAUTH_BCP_INSECURE_PLAINTEXT_TOKEN_STORAGE_ENABLED="
                "False) cannot be combined with a refresh-token grace period, which must "
                "return the previously issued token that is no longer stored in plaintext.",
                hint=(
                    "Set OAUTH2_PROVIDER['REFRESH_TOKEN_GRACE_PERIOD_SECONDS'] = 0, or keep "
                    "OAUTH_BCP_INSECURE_PLAINTEXT_TOKEN_STORAGE_ENABLED = True."
                ),
                id="oauth2_provider.E001",
            )
        )

    return messages


@checks.register(checks.Tags.database)
def validate_token_configuration(app_configs, **kwargs):
    databases = set(
        router.db_for_write(apps.get_model(model))
        for model in (
            oauth2_settings.ACCESS_TOKEN_MODEL,
            oauth2_settings.ID_TOKEN_MODEL,
            oauth2_settings.REFRESH_TOKEN_MODEL,
        )
    )

    # This is highly unlikely, but let's warn people just in case it does.
    # If the tokens were allowed to be in different databases this would require all
    # writes to have a transaction around each database. Instead, let's enforce that
    # they all live together in one database.
    # The tokens are not required to live in the default database provided the Django
    # routers know the correct database for them.
    if len(databases) > 1:
        return [checks.Error("The token models are expected to be stored in the same database.")]

    return []
