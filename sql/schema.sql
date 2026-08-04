-- Demo schema for the SQL proxy service.
-- Deliberately narrow blast radius: drops ONLY the two demo tables.
-- Never drops databases or schemas.

DROP TABLE IF EXISTS orders;
DROP TABLE IF EXISTS customers;

CREATE TABLE customers (
    id          SERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    email       TEXT NOT NULL UNIQUE,
    phone       TEXT,
    credit_card TEXT
);

CREATE TABLE orders (
    id          SERIAL PRIMARY KEY,
    customer_id INTEGER NOT NULL REFERENCES customers (id),
    amount      NUMERIC(10, 2) NOT NULL,
    created_at  TIMESTAMP NOT NULL DEFAULT now()
);
