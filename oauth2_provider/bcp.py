"""
Helpers for the RFC 9700 (OAuth 2.0 Security Best Current Practice) gates.

Each ``OAUTH_BCP_INSECURE_*_ENABLED`` setting guards a behavior that RFC 9700
discourages. The contract, implemented by :func:`bcp_insecure_behavior_allowed`,
is the same for every gate:

* ``True`` (the current default) — the insecure/legacy behavior is allowed, but a
  ``DeprecationWarning`` (and a log line) is emitted whenever the insecure path is
  actually exercised.
* ``False`` — the insecure behavior is not allowed; callers enforce the compliant
  behavior (reject the request, or perform the secure action instead).

The insecure defaults are scheduled to flip to ``False`` in the 4.0 release.
"""

import logging
import warnings

from .settings import oauth2_settings


log = logging.getLogger("oauth2_provider")


def bcp_warning_message(setting_name, behavior):
    """Build the standard warning/enforcement message for a gate."""
    return (
        f"{behavior} is discouraged by RFC 9700 (OAuth 2.0 Security Best Current "
        f"Practice). It is currently allowed because {setting_name}=True; this "
        f"default is scheduled to change to False in django-oauth-toolkit 4.0. Set "
        f"{setting_name}=False to adopt the compliant behavior now."
    )


def bcp_insecure_behavior_allowed(setting_name, behavior):
    """
    Return whether the insecure behavior gated by ``setting_name`` is allowed.

    Call this only on the insecure code path (i.e. when the discouraged behavior is
    actually being requested). When the gate is enabled a warning is emitted; when
    disabled the caller is expected to enforce the compliant behavior.

    :param setting_name: name of the ``OAUTH_BCP_INSECURE_*_ENABLED`` setting.
    :param behavior: human-readable description of the discouraged behavior, used in
        the warning message.
    :return: ``True`` if the legacy behavior may proceed, ``False`` if it must be
        prevented.
    """
    allowed = getattr(oauth2_settings, setting_name)
    if allowed:
        message = bcp_warning_message(setting_name, behavior)
        warnings.warn(message, DeprecationWarning, stacklevel=2)
        log.warning(message)
    return allowed
