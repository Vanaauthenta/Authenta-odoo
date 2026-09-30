"""Pure, framework-free helpers for the Authenta receipt verification flow.

Kept free of ORM access so the business rules (verdict mapping, overall expense
status, identifiers, PDF page counting, retry backoff) are easy to unit test.
"""

import io
from datetime import timedelta

SUPPORTED_CONTENT_TYPES = ("image/jpeg", "image/png", "application/pdf")
PDF_CONTENT_TYPE = "application/pdf"

# Authenta job status -> local verification state (before result interpretation)
NON_TERMINAL_JOB_STATUSES = ("initiated", "queued", "processing")
FAILED_JOB_STATUSES = ("failed", "cancelled", "deleted")

# Bounded retry policy for transient failures
MAX_TRANSIENT_ATTEMPTS = 8
BASE_BACKOFF_SECONDS = 60
MAX_BACKOFF_SECONDS = 3600

# Polling: stop waiting for a job after this long and surface an error
MAX_PROCESSING_AGE = timedelta(hours=24)


class ReceiptError(Exception):
    """A receipt that cannot be verified (unsupported, unreadable, too large...). Not retryable."""


def build_external_reference(db_uuid, attachment_id):
    """Opaque, stable reference Authenta stores with the job and returns for reconciliation."""
    return f"odoo:{db_uuid}:attachment:{attachment_id}"


def build_idempotency_key(db_uuid, verification_id, checksum):
    """Deterministic per verification attempt: retries reuse it, a re-verification (new record) gets a new one."""
    return f"odoo:{db_uuid}:verification:{verification_id}:{checksum or 'nochecksum'}"


def backoff_seconds(attempts):
    """Exponential backoff (60s, 120s, 240s, ...) capped at one hour."""
    return min(BASE_BACKOFF_SECONDS * (2 ** max(attempts - 1, 0)), MAX_BACKOFF_SECONDS)


def count_pdf_pages(data, reader_factory):
    """Returns the number of pages of a PDF, raising ReceiptError for invalid, encrypted or empty files.

    ``reader_factory`` is the PDF reader class (Odoo's ``odoo.tools.pdf.PdfFileReader``), injected for testability.
    """
    if not data:
        raise ReceiptError("The PDF receipt is empty.")
    try:
        reader = reader_factory(io.BytesIO(data), strict=False)
        if getattr(reader, "isEncrypted", False) or getattr(reader, "is_encrypted", False):
            decrypted = reader.decrypt("")
            if not decrypted:
                raise ReceiptError("The PDF receipt is password protected.")
        pages = len(reader.pages)
    except ReceiptError:
        raise
    except Exception as exc:  # PyPDF2 raises many exception types for corrupt input
        raise ReceiptError("The PDF receipt could not be read.") from exc
    if pages <= 0:
        raise ReceiptError("The PDF receipt has no pages.")
    return pages


def interpret_result(result):
    """Maps an Authenta job result to 'real', 'fake' or 'unknown'.

    Uses the classification the Authenta API already returns: ``isFake`` (all image/PDF detectors)
    and ``isTampered`` (document forgery). Either flag set means fake — the same rule the Authenta
    web app applies. A worker error payload or an unrecognised shape is 'unknown', never 'real'.
    """
    if not isinstance(result, dict) or "error" in result:
        return "unknown"
    flags = [result[key] for key in ("isFake", "isTampered") if isinstance(result.get(key), bool)]
    if not flags:
        return "unknown"
    return "fake" if any(flags) else "real"


def overall_status(verifications):
    """Aggregates the current verification of each receipt into the expense-level status.

    ``verifications`` is an iterable of ``(state, verdict)`` pairs for the expense's current
    (non-superseded) verifications. Rules: any FAKE -> 'fake'; all REAL -> 'real';
    otherwise 'error' if anything failed or is inconclusive, else 'processing'.
    No receipts -> 'none'. An error is never treated as verified.
    """
    items = list(verifications)
    if not items:
        return "none"
    if any(state == "completed" and verdict == "fake" for state, verdict in items):
        return "fake"
    if all(state == "completed" and verdict == "real" for state, verdict in items):
        return "real"
    if any(state in ("failed", "error") or (state == "completed" and verdict != "real") for state, verdict in items):
        return "error"
    return "processing"
