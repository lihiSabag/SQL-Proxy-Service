-- Seed data for the demo schema. All values are fabricated.
-- Coverage is deliberate:
--   - emails and phones for PII classification/masking demos;
--   - one NULL phone and one empty-string phone (NULL vs "" distinction);
--   - fake credit-card numbers (test-range 4111... etc.).

INSERT INTO customers (name, email, phone, credit_card) VALUES
    ('Lihi Roas',      'lihi.roas@example.com',      '0501230101', '4111111111111111'),
    ('Kim Perez',      'kim.perez@example.org',      '0524560102', '5555555555554444'),
    ('Daniel Mizrahi', 'daniel.mizrahi@example.net', NULL,         '378282246310009'),
    ('Yael Azulay',    'yael.azulay@example.com',    '',           NULL);

INSERT INTO orders (customer_id, amount, created_at) VALUES
    (1, 19.99,  '2026-07-01 10:00:00'),
    (1, 250.00, '2026-07-15 14:30:00'),
    (2, 5.49,   '2026-07-20 09:05:00'),
    (3, 999.90, '2026-07-28 18:45:00');
