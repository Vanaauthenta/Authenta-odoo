-- Neutralized (test/staging) copies must not send receipts to Authenta with the production credential.
DELETE FROM ir_config_parameter
 WHERE key IN (
    'authenta_expense.enabled',
    'authenta_expense.api_key',
    'authenta_expense.integration_id',
    'authenta_expense.connected_tenant',
    'authenta_expense.connected_db_uuid',
    'authenta_expense.connect_pending'
 );
