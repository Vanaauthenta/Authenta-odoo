# Authenta Receipt Verification for Odoo 17 (`authenta_expense`)

Automatically verifies every expense receipt with [Authenta](https://authenta.ai) and blocks approval of expense
reports containing a fake receipt. Odoo 17 Community, depends only on `hr_expense`. Results are obtained by polling.

```
├── authenta_expense/              # the Odoo addon
│   ├── models/
│   │   ├── res_config_settings.py # admin settings: Connect / Test Connection / Disconnect
│   │   ├── authenta_verification.py # one record per receipt verification attempt; submit/poll crons
│   │   ├── hr_expense.py          # expense/sheet verification status + approval gating
│   │   └── ir_attachment.py       # detects new receipts (create/write hooks)
│   ├── controllers/connect.py     # /authenta/connect/callback (admins only)
│   ├── services/
│   │   ├── authenta_client.py     # HTTP client with typed errors (no secrets or URLs logged)
│   │   └── receipt_logic.py       # pure rules: verdict, overall status, keys, PDF pages, backoff
│   ├── security/, data/ir_cron.xml, views/, static/description/, tests/
```

## Setup

1. **Install the addon** in Odoo (copy `authenta_expense` into your addons path, *Apps → Update Apps List → Authenta Receipt Verification*).
   Make sure Odoo's `web.base.url` is the URL administrators use in their browser — Authenta sends them back to
   `<web.base.url>/authenta/connect/callback`.
2. **Connect**: *Expenses → Configuration → Settings → Authenta Receipt Verification* (Settings administrators only), click
   **Connect**. The module uses the Authenta service by default; URL overrides exist only in developer mode (*Advanced connection
   settings*) and are needed only if Authenta support asks. You are taken to Authenta, log in as an owner/admin of your Authenta
   organization, review the connection and click **Authorize**. Authenta sends you back to Odoo, which shows *Connected to Authenta tenant …*.
   No API key is copied: Odoo receives a one-time code and exchanges it server-to-server (PKCE-protected) for its own integration key.
3. **Test Connection** (shown once connected): validates the key, that the integration is an active Odoo integration, that the key has
   `ReadJob` + `WriteJob`, and which receipt types are mapped to available task types.
4. **Task mapping** defaults to Authenta's *document-intelligence* task for JPEG/PNG and *pdf-tampering-detection* for PDF (when available
   to your organization). It can be changed in Authenta (`PATCH /integrations/:id`); Odoo reads it on every submission run.
5. **Enable** "Verify receipts with Authenta" and save.
6. **Disconnect** revokes the key in Authenta and removes it from Odoo. Connecting the same Odoo database again reuses its Authenta
   integration and issues a new key.

### Manual configuration (existing installations)

Installations configured with a pasted API key keep working unchanged. A key can also be entered directly under the **Connect** button
("Or enter an integration API key manually", then **Save & Test**): create the integration with `POST /api/v1/integrations`
(`{"provider": "odoo", "name": "Odoo – Production", "config": {"taskTypeMapping": {...}}}`) and paste the returned `apiKey.token`.
To switch an existing installation to the connect flow, click **Disconnect** and then **Connect**.

## How it works

1. An employee attaches a receipt to an expense as usual (upload, "create expense from receipt", chatter...).
2. The `ir.attachment` hook creates an `authenta.verification` record (`pending`) — no network call in the employee's request — and
   triggers the *submit* cron.
3. The cron validates the file (JPEG/PNG/PDF, size, PDF page count via Odoo's bundled PyPDF2), calls `POST /jobs` with a deterministic
   `Idempotency-Key` (`odoo:<database uuid>:verification:<id>:<checksum>`), an external reference
   (`odoo:<database uuid>:attachment:<id>`) and metadata, uploads the file to the presigned URL (no Authorization header, exact
   Content-Type/Length) and finalizes the job → `submitted`.
4. The *poll* cron (every 2 min, per-record backoff) calls `GET /jobs/:id`: `processing` → `completed` with verdict **real/fake/unknown**
   (`isFake`/`isTampered` from the Authenta result), or `failed` if Authenta could not process it. The raw result is kept for managers.
5. The expense's **Receipt Verification** status: any FAKE → *Fake Receipt*; all REAL → *Verified*; any failure/inconclusive → *Not Verified*;
   otherwise *Verifying*. The report aggregates its expenses the same way.
6. Approving a report (and posting its journal entries) is refused while any expense is *Fake Receipt*, *Verifying* or *Not Verified*,
   with a message explaining why. Refusing a report is always possible. Expenses without receipts are not blocked.

## Employee behaviour

Employees add receipts normally and never configure or see Authenta credentials. They see the verification status and reason on their
expense (and a chatter note), and they cannot get an expense report with a FAKE receipt approved.

## Managers and administrators

- *Expenses → Reporting → Receipt Verifications* lists verification attempts (team approvers see their team's, all-approvers see all).
- Expense administrators can **Retry** an errored verification (same idempotency key — no duplicate Authenta job or charge) — e.g. after
  fixing credentials or topping up credits — or **Re-verify** a receipt (new attempt, new key, new billable job; the previous attempt is kept
  as history).

## Error handling

| Situation                                   | Result                                                                    |
| ------------------------------------------- | ------------------------------------------------------------------------- |
| Network error, timeout, HTTP 5xx/429        | retried with exponential backoff (60 s … 1 h), gives up after 8 attempts → *Not Verified* |
| Authenta unreachable when a batch starts    | batch postponed, nothing consumed                                         |
| Upload rejected / URL expired               | retried; the same idempotency key returns a fresh upload URL              |
| Finalize already done (409)                 | treated as success                                                        |
| 401 invalid/rotated key, 403 disabled/forbidden, 402 no credits | *Not Verified* with an admin-actionable message; no retry loop (use Retry after fixing) |
| Unsupported type, too large, unreadable/encrypted/empty PDF | *Not Verified* immediately, nothing sent                  |
| Authenta job failed/cancelled               | *Not Verified* — a processing failure is never treated as fake or real    |
| No result after 24 h                        | *Not Verified*                                                            |

## Security

- Credentials are stored in `ir.config_parameter` (readable only by Settings administrators); the settings form never sends the stored key
  back to the browser.
- Verification technical fields (job ID, idempotency key, raw result) are restricted to expense administrators; employees can read only
  verifications of their own expenses (record rules mirror `hr_expense`), nobody can create/delete them through the UI.
- The client never logs API keys, presigned URLs or receipt contents.
- Connect flow: the `state` and PKCE verifier are generated server-side, stored admin-only, bound to the administrator who clicked
  **Connect**, valid for 10 minutes and single-use. The callback is restricted to Settings administrators; connection codes and verifiers are
  never logged. Authenta only issues codes to its tenant admins, binds them to this database's UUID and callback URL, and accepts each once.

## Tests

```bash
odoo -d authenta_test -i authenta_expense --test-enable --test-tags /authenta_expense --stop-after-init --without-demo=all
```
