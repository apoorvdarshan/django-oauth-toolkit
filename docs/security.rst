RFC 9700 Security Best Current Practice
=======================================

`RFC 9700 <https://datatracker.ietf.org/doc/html/rfc9700>`_ ("Best Current Practice
for OAuth 2.0 Security", BCP 240) updates and extends the security advice in
`RFC 6749 <https://datatracker.ietf.org/doc/html/rfc6749>`_,
`RFC 6750 <https://datatracker.ietf.org/doc/html/rfc6750>`_, and
`RFC 6819 <https://datatracker.ietf.org/doc/html/rfc6819>`_. This page maps each
relevant recommendation to django-oauth-toolkit (DOT) behavior and the setting that
controls it.

.. _rfc9700-gates:

Gated behaviors and the 3.4 → 4.0 transition
--------------------------------------------

Several behaviors that RFC 9700 discourages are still enabled by default so that
upgrading does not change how an existing deployment behaves. Each is controlled by
an ``OAUTH_BCP_INSECURE_<behavior>_ENABLED`` boolean:

* ``True`` (the current default) — the insecure/legacy behavior is allowed, but a
  ``DeprecationWarning`` is emitted whenever it is exercised.
* ``False`` — the behavior is enforced: the insecure request is rejected, or the
  secure behavior is performed instead.

**These defaults are scheduled to flip to** ``False`` **in the 4.0 release.** Set them
to ``False`` now to adopt the compliant behavior early and silence the warnings.

Run ``python manage.py check --deploy`` to get a checklist of every gate (and the two
existing settings below) that is currently on its non-compliant value.

Compliant settings block
-------------------------

To adopt the full set of RFC 9700 recommendations today, add the following to your
``OAUTH2_PROVIDER`` setting::

    OAUTH2_PROVIDER = {
        # ... your existing settings ...

        # RFC 9700 gates (default True today; will default False in 4.0)
        "OAUTH_BCP_INSECURE_IMPLICIT_GRANT_ENABLED": False,
        "OAUTH_BCP_INSECURE_PASSWORD_GRANT_ENABLED": False,
        "OAUTH_BCP_INSECURE_PKCE_PLAIN_ENABLED": False,
        "OAUTH_BCP_INSECURE_ACCESS_TOKEN_IN_QUERY_ENABLED": False,
        "OAUTH_BCP_INSECURE_OMIT_AUTHZ_ISS_ENABLED": False,

        # Existing settings whose defaults also change in 4.0
        "REFRESH_TOKEN_REUSE_PROTECTION": True,
        "ALLOWED_REDIRECT_URI_SCHEMES": ["https"],

        # Optional, opt-in hardening (see the caveat below)
        # "OAUTH_BCP_INSECURE_PLAINTEXT_TOKEN_STORAGE_ENABLED": False,
    }

Recommendation-by-recommendation
--------------------------------

PKCE (§2.1.1)
~~~~~~~~~~~~~
PKCE is required by default (``PKCE_REQUIRED`` is ``True``). RFC 9700 also
discourages the ``plain`` ``code_challenge_method`` in favor of ``S256``; set
``OAUTH_BCP_INSECURE_PKCE_PLAIN_ENABLED = False`` to reject ``plain`` challenges and
drop it from the authorization-server metadata.

Redirect URI matching (§2.1)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
DOT already performs exact redirect-URI matching (scheme, host, port, and path),
with wildcards off (``ALLOW_URI_WILDCARDS`` defaults to ``False``) and the
`RFC 8252 <https://datatracker.ietf.org/doc/html/rfc8252>`_ loopback exemption off by
default. Set ``ALLOWED_REDIRECT_URI_SCHEMES = ["https"]`` to disallow registering
plaintext ``http`` redirect URIs; loopback ``http`` for native apps remains available
through ``ALLOW_LOCALHOST_LOOPBACK``.

Implicit grant (§2.1.2)
~~~~~~~~~~~~~~~~~~~~~~~~
The implicit grant MUST NOT be used. Set
``OAUTH_BCP_INSECURE_IMPLICIT_GRANT_ENABLED = False`` to reject the ``token`` /
``id_token`` response types and stop advertising ``implicit`` in the
authorization-server metadata.

Resource owner password credentials grant (§2.4)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The password grant MUST NOT be used. Set
``OAUTH_BCP_INSECURE_PASSWORD_GRANT_ENABLED = False`` to reject
``grant_type=password`` and stop advertising it.

Access tokens in the query string (§4.3.2)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Access tokens MUST NOT be transmitted in the URI query string. Set
``OAUTH_BCP_INSECURE_ACCESS_TOKEN_IN_QUERY_ENABLED = False`` to reject requests that
present an ``access_token`` query parameter at the resource server. The
``Authorization`` header (and form-encoded body per
`RFC 6750 <https://datatracker.ietf.org/doc/html/rfc6750>`_) are unaffected.

Mix-up attacks / issuer identification (§4.4, RFC 9207)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Set ``OAUTH_BCP_INSECURE_OMIT_AUTHZ_ISS_ENABLED = False`` to include the ``iss``
parameter (`RFC 9207 <https://datatracker.ietf.org/doc/html/rfc9207>`_) in the
authorization response and advertise
``authorization_response_iss_parameter_supported`` in the metadata. The ``iss``
value matches the metadata ``issuer`` (``OIDC_ISS_ENDPOINT`` when configured,
otherwise derived from the request).

Refresh-token rotation and replay detection (§4.14)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Rotation is on by default (``ROTATE_REFRESH_TOKEN``). Set
``REFRESH_TOKEN_REUSE_PROTECTION`` to ``True`` to revoke the entire token family when
a refresh token is replayed (§4.14.2). Note that reuse detection only treats a replay
as an attack after ``REFRESH_TOKEN_GRACE_PERIOD_SECONDS``.

Token storage at rest (§4)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
By default DOT stores access and refresh tokens in cleartext (alongside a SHA-256
``token_checksum`` used for lookup). Set
``OAUTH_BCP_INSECURE_PLAINTEXT_TOKEN_STORAGE_ENABLED = False`` to store only the
token hash, so a database read no longer discloses usable tokens. Existing cleartext
tokens are left in place and age out as they expire or rotate.

.. warning::
   Hashed token storage is incompatible with the refresh-token grace period, which
   must return a previously issued (cleartext) token from the database. When
   ``OAUTH_BCP_INSECURE_PLAINTEXT_TOKEN_STORAGE_ENABLED`` is ``False`` you must set
   ``REFRESH_TOKEN_GRACE_PERIOD_SECONDS = 0`` (the default); ``manage.py check``
   raises ``oauth2_provider.E001`` otherwise.

Out of scope
------------

Sender-constrained access tokens (DPoP,
`RFC 9449 <https://datatracker.ietf.org/doc/html/rfc9449>`_, and mutual-TLS,
`RFC 8705 <https://datatracker.ietf.org/doc/html/rfc8705>`_; RFC 9700 §2.2/§4.13) are
not implemented. DOT issues bearer tokens only.
