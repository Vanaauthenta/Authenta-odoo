import io

from odoo.tests import BaseCase, tagged
from odoo.tools.pdf import PdfFileReader, PdfFileWriter

from ..services.receipt_logic import (
    ReceiptError,
    backoff_seconds,
    build_external_reference,
    build_idempotency_key,
    count_pdf_pages,
    interpret_result,
    overall_status,
)


def make_pdf(pages):
    writer = PdfFileWriter()
    for _index in range(pages):
        writer.addBlankPage(width=200, height=200)
    stream = io.BytesIO()
    writer.write(stream)
    return stream.getvalue()


@tagged("post_install", "-at_install", "authenta")
class TestReceiptLogic(BaseCase):
    def test_interpret_document_result_real(self):
        self.assertEqual(interpret_result({"isFake": False, "isTampered": False, "confidence": 0.1}), "real")

    def test_interpret_document_result_tampered_is_fake(self):
        self.assertEqual(interpret_result({"isFake": False, "isTampered": True}), "fake")

    def test_interpret_pdf_result_fake(self):
        self.assertEqual(interpret_result({"isFake": True, "fakePages": 1, "totalPages": 2}), "fake")

    def test_interpret_worker_error_is_unknown(self):
        self.assertEqual(interpret_result({"error": "OutOfMemoryError", "message": "boom"}), "unknown")

    def test_interpret_unrecognised_shape_is_unknown(self):
        self.assertEqual(interpret_result({"score": 0.4}), "unknown")
        self.assertEqual(interpret_result(None), "unknown")

    def test_overall_no_receipts(self):
        self.assertEqual(overall_status([]), "none")

    def test_overall_real_real(self):
        self.assertEqual(overall_status([("completed", "real"), ("completed", "real")]), "real")

    def test_overall_real_fake(self):
        self.assertEqual(overall_status([("completed", "real"), ("completed", "fake")]), "fake")

    def test_overall_fake_fake(self):
        self.assertEqual(overall_status([("completed", "fake"), ("completed", "fake")]), "fake")

    def test_overall_fake_wins_over_error(self):
        self.assertEqual(overall_status([("error", "unknown"), ("completed", "fake")]), "fake")

    def test_overall_error_is_not_verified(self):
        self.assertEqual(overall_status([("completed", "real"), ("error", "unknown")]), "error")
        self.assertEqual(overall_status([("failed", "unknown")]), "error")
        self.assertEqual(overall_status([("completed", "unknown")]), "error")

    def test_overall_pending_is_processing(self):
        self.assertEqual(overall_status([("completed", "real"), ("processing", "unknown")]), "processing")
        self.assertEqual(overall_status([("pending", "unknown")]), "processing")

    def test_idempotency_key_is_deterministic_per_attempt(self):
        first = build_idempotency_key("db-uuid", 7, "abc")
        self.assertEqual(first, build_idempotency_key("db-uuid", 7, "abc"))
        self.assertNotEqual(first, build_idempotency_key("db-uuid", 8, "abc"))
        self.assertLessEqual(len(build_idempotency_key("x" * 36, 10**9, "f" * 40)), 255)

    def test_external_reference_format(self):
        self.assertEqual(build_external_reference("db-uuid", 42), "odoo:db-uuid:attachment:42")

    def test_backoff_is_bounded(self):
        self.assertEqual(backoff_seconds(1), 60)
        self.assertEqual(backoff_seconds(2), 120)
        self.assertEqual(backoff_seconds(20), 3600)

    def test_count_pdf_pages(self):
        self.assertEqual(count_pdf_pages(make_pdf(3), PdfFileReader), 3)

    def test_count_pdf_pages_invalid(self):
        with self.assertRaises(ReceiptError):
            count_pdf_pages(b"not a pdf at all", PdfFileReader)

    def test_count_pdf_pages_empty(self):
        with self.assertRaises(ReceiptError):
            count_pdf_pages(b"", PdfFileReader)
