"""Thin HTTP client for the Authenta public API used by the expense connector.

Only this module talks HTTP. It never logs API keys, presigned URLs or file
contents, and it converts every failure into a typed ``AuthentaError`` so the
caller can decide between retrying, reporting a configuration problem, or
recording a verification error.
"""

import logging
from urllib.parse import urlencode

import requests

_logger = logging.getLogger(__name__)

CONNECT_TIMEOUT = 10
READ_TIMEOUT = 30
UPLOAD_READ_TIMEOUT = 120


class AuthentaError(Exception):
    """Base error. ``retryable`` tells the caller whether the same call may succeed later."""

    retryable = False
    kind = "error"

    def __init__(self, message, status_code=None, code=None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.code = code


class AuthentaTransientError(AuthentaError):
    """Network failure, timeout, 5xx or 429 — safe to retry with the same idempotency key."""

    retryable = True
    kind = "transient"


class AuthentaAuthError(AuthentaError):
    """401 — the API key is missing, wrong, rotated, expired or revoked."""

    kind = "auth"


class AuthentaForbiddenError(AuthentaError):
    """403 — insufficient permissions, disabled integration or suspended tenant."""

    kind = "forbidden"


class AuthentaBillingError(AuthentaError):
    """402 — the Authenta tenant has no credits / PAYG capacity. Needs an administrator."""

    kind = "billing"


class AuthentaConflictError(AuthentaError):
    """409 — e.g. idempotency key reused with a different payload, or upload already finalized."""

    kind = "conflict"


class AuthentaRequestError(AuthentaError):
    """Other 4xx — the request itself is invalid (validation error, unknown job, file too large...)."""

    kind = "request"


class AuthentaUploadError(AuthentaTransientError):
    """The presigned upload was rejected (expired/mismatched URL) — re-initiate with the same key."""

    kind = "upload"


def _error_from_response(response):
    try:
        body = response.json()
    except ValueError:
        body = {}
    code = body.get("name") if isinstance(body, dict) else None
    message = body.get("message") if isinstance(body, dict) else None
    message = message or f"Authenta returned HTTP {response.status_code}"
    status = response.status_code
    if status == 401:
        return AuthentaAuthError(message, status, code)
    if status == 402:
        return AuthentaBillingError(message, status, code)
    if status == 403:
        return AuthentaForbiddenError(message, status, code)
    if status == 409:
        return AuthentaConflictError(message, status, code)
    if status == 429 or status >= 500:
        return AuthentaTransientError(message, status, code)
    return AuthentaRequestError(message, status, code)


def _api_base_url(base_url):
    base_url = base_url.rstrip("/")
    return base_url if base_url.endswith("/api/v1") else f"{base_url}/api/v1"


def build_authorize_url(base_url, params):
    """URL of Authenta's connect entry point; Authenta validates it and redirects the admin to the consent screen."""
    return f"{_api_base_url(base_url)}/integrations/connect/authorize?{urlencode(params)}"


class AuthentaClient:
    """Authenta API client bound to one base URL and integration API key."""

    def __init__(self, base_url, api_key, session=None):
        if not base_url or not api_key:
            raise AuthentaAuthError("Authenta base URL and API key must be configured")
        self.base_url = _api_base_url(base_url)
        self._api_key = api_key
        self._session = session or requests.Session()

    @classmethod
    def unauthenticated(cls, base_url, session=None):
        """Client without an API key, used only to redeem a connection code."""
        if not base_url:
            raise AuthentaRequestError("Authenta base URL must be configured")
        client = cls.__new__(cls)
        client.base_url = _api_base_url(base_url)
        client._api_key = None
        client._session = session or requests.Session()
        return client

    def __repr__(self):
        return f"<AuthentaClient {self.base_url}>"

    def _headers(self, extra=None):
        headers = {"Accept": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        if extra:
            headers.update(extra)
        return headers

    def _request(self, method, path, json=None, params=None, headers=None):
        url = f"{self.base_url}{path}"
        try:
            response = self._session.request(
                method,
                url,
                json=json,
                params=params,
                headers=self._headers(headers),
                timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            )
        except requests.Timeout as exc:
            raise AuthentaTransientError(f"Timed out calling Authenta {method} {path}") from exc
        except requests.RequestException as exc:
            raise AuthentaTransientError(f"Could not reach Authenta ({exc.__class__.__name__})") from exc
        if response.status_code >= 400:
            error = _error_from_response(response)
            _logger.info("Authenta %s %s failed: HTTP %s %s", method, path, error.status_code, error.code)
            raise error
        if response.status_code == 204 or not response.content:
            return {}
        try:
            return response.json()
        except ValueError as exc:
            raise AuthentaTransientError("Authenta returned a non-JSON response") from exc

    def test_connection(self):
        """GET /integrations/current — describes the integration behind the key."""
        return self._request("GET", "/integrations/current")

    def exchange_connection_code(self, code, code_verifier, redirect_uri, instance_id):
        """POST /integrations/connect/token — redeems a one-time connection code for the integration API key.

        The code and verifier are secrets: they are never logged.
        """
        body = {"code": code, "codeVerifier": code_verifier, "redirectUri": redirect_uri, "instanceId": instance_id}
        return self._request("POST", "/integrations/connect/token", json=body)

    def disconnect(self):
        """POST /integrations/current/disconnect — disables the integration and revokes this key."""
        return self._request("POST", "/integrations/current/disconnect")

    def create_job(self, task_type_id, slot_name, file_name, content_type, size_bytes, idempotency_key,
                   external_reference, external_metadata=None, page_count=None):
        """POST /jobs with an Idempotency-Key. Returns ``(job, inputs)``."""
        upload = {"slotName": slot_name, "fileName": file_name, "contentType": content_type, "sizeBytes": size_bytes}
        if page_count:
            upload["pageCount"] = page_count
        body = {"taskTypeId": str(task_type_id), "inputs": [upload], "externalReference": external_reference}
        if external_metadata:
            body["externalMetadata"] = external_metadata
        data = self._request("POST", "/jobs", json=body, headers={"Idempotency-Key": idempotency_key})
        return data.get("job") or {}, data.get("inputs") or []

    def upload_file(self, upload_url, data, content_type):
        """PUT the file to the presigned URL.

        The URL is pre-authorised: no Authorization header is sent, and the
        Content-Type / Content-Length must match what was declared at job creation.
        """
        headers = {"Content-Type": content_type, "Content-Length": str(len(data))}
        try:
            response = self._session.put(upload_url, data=data, headers=headers, timeout=(CONNECT_TIMEOUT, UPLOAD_READ_TIMEOUT))
        except requests.Timeout as exc:
            raise AuthentaUploadError("Timed out uploading the receipt") from exc
        except requests.RequestException as exc:
            raise AuthentaUploadError(f"Could not upload the receipt ({exc.__class__.__name__})") from exc
        if response.status_code >= 400:
            # Deliberately do not log the URL: it is a bearer credential until it expires.
            raise AuthentaUploadError(f"Receipt upload was rejected (HTTP {response.status_code})", response.status_code)

    def finalize_job(self, job_id):
        """POST /jobs/:id/finalize. An already-finalized job is treated as success (safe retry)."""
        try:
            return self._request("POST", f"/jobs/{job_id}/finalize")
        except AuthentaConflictError as exc:
            if exc.code == "UPLOAD_ALREADY_FINALIZED":
                return None
            raise

    def get_job(self, job_id):
        """GET /jobs/:id."""
        return self._request("GET", f"/jobs/{job_id}")
