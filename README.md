# SQL Proxy Service

A security-focused SQL proxy for PostgreSQL.

The service receives SQL statements, analyzes them before execution, applies a fail-closed access policy, executes approved queries, classifies sensitive result columns, masks PII, and writes structured audit records.

The implementation prioritizes four goals:

- Make security decisions explicit and predictable.
- Reject SQL that cannot be analyzed safely.
- Keep business logic independent from infrastructure libraries.
- Minimize sensitive data exposure throughout the pipeline.

## Assignment coverage

| Evaluation area | Implementation |
|---|---|
| SQL Analysis | AST-based parsing with `hyrise/sql-parser`, followed by a parser-independent analysis model. |
| Correctness of SQL Analysis | Unsupported, unparseable, or ambiguous SQL is rejected instead of being partially interpreted. |
| Masking Enforcement | Masking is centralized, deterministic, and applied before results leave the service. |
| Classification Logic | Query analysis is combined with actual result-column metadata. Unknown attribution is kept separate from non-PII. |
| Audit Quality | Query outcomes are stored as structured JSON Lines records without SQL text, values, identifiers, or driver error messages. |
| System Log | Startup, configuration, server lifecycle, and audit persistence failures are logged separately from the audit trail. |
| Data Setup | Docker Compose initializes PostgreSQL from version-controlled schema and seed scripts. |
| Overall Design | Core logic is separated from HTTP, SQL parser, PostgreSQL, and file-persistence details through project-owned interfaces. |

## Architecture

![SQL Proxy Service Architecture](architecture.png)

`ProxyService` coordinates the request flow. Each stage has one responsibility:

| Component | Responsibility |
|---|---|
| `SqlAnalyzer` | Converts parser output into the project's SQL analysis model. |
| `PolicyEngine` | Decides whether the analyzed statement may execute. |
| `IQueryExecutor` | Defines the database-neutral execution contract. |
| `DataClassifier` | Attributes result columns and identifies PII categories. |
| `PiiMasker` | Applies deterministic masking to classified values. |
| `IAuditRepository` | Persists structured request outcomes. |

Third-party types remain inside their adapters:

- Hyrise types stay inside the SQL parser adapter.
- libpqxx types stay inside the PostgreSQL adapter.
- cpp-httplib types stay inside the HTTP adapter.

The core depends only on project-defined types and interfaces. This keeps it independently testable and prevents infrastructure libraries from defining business behavior.

## Why this design?

### SQL analysis

**Why?**

Security decisions cannot safely depend on string matching. Comments, quoting, aliases, casing, and nested syntax make text-based SQL inspection unreliable.

**Implementation**

The service parses SQL into a real AST using `hyrise/sql-parser`. The adapter converts parser-specific objects into a project-owned `ParsedStatement`, and `SqlAnalyzer` produces a parser-independent `SqlAnalysis`.

The analysis records, on a best-effort basis:

- statement type and class;
- statement count;
- referenced tables;
- SELECT projection columns;
- DML affected columns;
- wildcard and computed-projection flags;
- whether the projection is a canonical `COUNT(*)`;
- whether the statement has a `GROUP BY`;
- unsupported features.

**Trade-off**

The service supports a bounded SQL subset. SQL that cannot be understood confidently is rejected. Broader coverage is valuable only if it preserves fail-closed behavior.

### Policy enforcement

**Why?**

The service does not implement authentication, user identity, or roles. Without a trusted identity it cannot decide whether a caller may modify data in general, so writes are refused as a class rather than authorized case by case.

**Implementation**

The proxy is read-only apart from one explicitly enumerated write:

- supported single-statement `SELECT` queries may proceed;
- one exact `INSERT` shape may proceed (see below);
- all other DML, and every DDL statement, are rejected before execution;
- multiple statements are rejected;
- unsupported statement types and features are rejected;
- system-catalog access is rejected;
- projection shapes that cannot be handled safely are rejected.

Policy decisions use typed rejection reasons rather than free-form strings.

**The single permitted write**

```sql
INSERT INTO orders (customer_id, amount) VALUES (1, 199.90);
```

It is authorized only when every one of these holds: exactly one statement, target table exactly `orders` unqualified, an explicit column list of exactly `customer_id` then `amount` in that order, a `VALUES` source, and two values that are a positive integer literal and a positive numeric literal. Identifier comparison is exact and case-sensitive, stricter than the read path, so a write is refused whenever the target is not spelled canonically.

Everything else stays rejected, including `INSERT ... SELECT`, multiple rows, `RETURNING`, `DEFAULT`, functions, arithmetic, subqueries, an omitted column list, reordered or duplicated columns, zero and negative values, a qualified name such as `public.orders`, and any casing other than the canonical one. `UPDATE`, `DELETE` and `TRUNCATE` are unaffected.

`INSERT ... SELECT` is rejected on its source form rather than its table list, because the current parser model records only the target table and its table list is therefore indistinguishable from a permitted insert's.

An authorized insert returns `200` with `{"affected_rows": 1}` and no result set. Every rejected write returns the same generic `403` as any other policy denial, so the rule set cannot be mapped by probing; the precise reason is kept in the audit trail only. A foreign-key or constraint failure returns `400` with no constraint name or value.

If the database reports success but an affected-row count other than one, the service reports an internal failure (`500`). This check runs only after the transaction has committed and indicates that the database behaved outside the assumptions of the proxy policy, for example because of a trigger or rewrite rule.

Because the parser strips quotes without reporting them, `INSERT INTO "orders"` cannot be distinguished from the unquoted form. Both forms resolve to the same relation, so this does not expand the permitted write surface. Qualified names such as `public."orders"` and differently cased identifiers such as `"Orders"` remain rejected.

The PostgreSQL account should also use a least-privilege role, granted `SELECT` on the tables it reads plus column-level `INSERT` on exactly `orders(customer_id, amount)`. The application policy is one layer of protection, not a replacement for database permissions.

**Trade-off**

Allowing one write shape rather than general `INSERT` support keeps the authorization rule small enough to read in full, at the cost of rejecting statements that are harmless in practice, such as `COUNT(1)`-style equivalents of the permitted form. Business limits on the value itself stay in the database schema, where `NUMERIC(10,2)` and the foreign key already enforce them.

### Classification logic

**Why?**

A sensitive column must not be treated as safe simply because its source cannot be determined.

**Implementation**

Classification combines:

- the analyzed SELECT projection;
- the column metadata returned by PostgreSQL;
- a configurable, case-insensitive mapping of known PII column names.

Each result column receives one of three states:

- `Pii`
- `NotClassifiedAsPii`
- `Unattributed`

`Unattributed` is intentionally distinct from non-PII. The classifier never guesses when attribution is incomplete.

The supported PII categories are:

- `PII.Email`
- `PII.Phone`
- `PII.CreditCard`

The classifier receives column metadata only. It does not inspect row values, so sensitive values cannot enter or leak from the classification component.

**Aggregates: the canonical `COUNT(*)`**

Computed expressions normally cannot be attributed to a source column, so they are refused. One shape is recognized as safe and executed: the canonical `COUNT(*)`. It counts rows and never reads the contents of a column, so its result has no lineage to any stored value and cannot carry PII.

Recognition happens in the parser adapter and is deliberately narrow. It requires a `COUNT` call, without `DISTINCT`, without a window clause, with exactly one argument that is the star. Attribution is then by shape rather than by name, so `SELECT COUNT(*) AS email` is still a count and is returned intact rather than masked.

Everything else in the family remains refused exactly as before, including `COUNT(1)`, `COUNT(NULL)`, `COUNT(column)`, `COUNT(DISTINCT column)`, `COUNT(*) OVER (...)`, `COUNT(*) + 1`, `MIN`/`MAX`/`SUM`/`AVG`, any grouped count, and any projection that mixes a count with a column, a wildcard, or another expression.

**Trade-off**

Metadata-based classification is predictable and testable, but it cannot identify sensitive data stored under an unexpected or misleading column name.

Supporting only the canonical `COUNT(*)` means `COUNT(1)` is rejected even though SQL treats the two as equivalent. That is deliberate: the goal is one well-defined safe shape rather than a family of variants, and each additional form widens the surface that has to be kept safe.

### Masking enforcement

**Why?**

Sensitive values must be transformed before any successful result leaves the proxy.

**Implementation**

Masking occurs after execution and classification, using the actual result-column order.

The rules are deterministic and category-specific:

```text
Email
lihi.roas@example.com -> l***@example.com

Phone
0501230101 -> ***0101

Credit card
4111111111111111 -> ****1111
```

The same category always follows the same masking rule.

`NULL` remains `NULL`, and an empty string remains an empty string. The masker does not invent values where none exist.

Before changing any result cell, the masker validates the complete classification and result shape. If masking cannot be applied safely, no partially masked result is returned.

**Trade-off**

The implementation uses deterministic redaction rather than tokenization, encryption, or reversible masking. These techniques provide different operational properties but are outside the scope of this service.

### Audit quality

**Why?**

An audit trail should record request outcomes without becoming another source of sensitive-data leakage.

**Implementation**

Every request handled by the SQL pipeline produces one structured JSON Lines audit record.

The record uses closed enums and numeric fields, plus a validated list of referenced table names. It excludes:

- raw or normalized SQL;
- query values and literals;
- column names and aliases;
- result values;
- database error messages;
- connection strings;
- file paths.

Successful results are not returned if the audit record cannot be persisted.

**Referenced tables**

Records that follow a successful analysis carry the tables the statement named, so the trail can answer which tables a request touched:

```json
{"outcome":"SUCCESS","statement_type":"SELECT","referenced_tables":["customers","orders"], ...}
{"outcome":"POLICY_REJECTED","reason":"SYSTEM_TABLE_ACCESS","referenced_tables":["pg_authid"], ...}
{"outcome":"SUCCESS","statement_type":"SELECT","referenced_tables_omitted":true, ...}
```

A name is recorded only if it is a plain unqualified ASCII identifier: 1 to 63 bytes, starting with a letter or underscore, continuing with letters, digits, underscores or dollar signs. At most eight names are kept. Qualified references such as `public.customers`, and anything containing a dot, whitespace, a control character or a byte outside that set, fail the check.

Validation is all-or-nothing. If any name fails, or there are too many, the whole list is dropped and the record carries `"referenced_tables_omitted": true` instead. Names are never truncated, and a partial list is never written, because a partial list would read as a complete one. When no analyzed tables exist, such as after a parse failure, neither key appears: the trail never claims "no tables" when the truth is "not known". Parsing failures and internal failures never carry the metadata at all, because their record factories do not accept it.

**Omitting the metadata never changes the SQL request.** The policy decision, the HTTP status and the response body are identical either way.

**Trade-off**

Recording table names adds forensic value but widens what the audit stores. The strict whitelist is what keeps that safe: a rejected statement's table name is caller-controlled text, and without validation a crafted identifier could break strict JSON serialization and cost the entire audit line. Column names remain excluded, since they are more numerous and sit closer to the data than table names do.

### System log

The system log is separate from the audit trail.

It currently records operational events such as:

- startup and configuration;
- the HTTP listening port;
- startup failures;
- audit persistence failures.

It does not log SQL, identifiers, values, or database error text.

Request-level latency, status metrics, and operational counters are possible future improvements.

## Data setup

The repository includes a demonstration schema and fabricated seed data:

```text
sql/
├── schema.sql
└── seed.sql
```

The schema contains `customers` and `orders`. The dataset covers:

- email, phone, and credit-card masking;
- joins and wildcard projections;
- aliases;
- `NULL` and empty-string behavior;
- allowed and rejected policy outcomes.

All stored card numbers are publicly documented, non-transactable test values.

### Least-privilege database role

The proxy's own policy is one layer; database privileges are the boundary that holds if it is bypassed. Grant the service role only what the two supported capabilities need:

```sql
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM sql_proxy_user;

-- Reads
GRANT SELECT ON customers, orders TO sql_proxy_user;

-- The single permitted write, restricted to two columns
GRANT INSERT (customer_id, amount) ON orders TO sql_proxy_user;

-- orders.id is a SERIAL, so its sequence must be usable by the insert
GRANT USAGE ON SEQUENCE orders_id_seq TO sql_proxy_user;
```

`USAGE` on the sequence permits `nextval` only, not `setval`, and it is required: without it an authorized insert fails at runtime even though the policy allowed it.

Not granted: `UPDATE`, `DELETE`, `TRUNCATE`, any DDL, `INSERT` on `customers`, and `INSERT` on `orders.id` or `orders.created_at`. Under these grants the role cannot modify an existing row anywhere, and cannot write to `customers` at all, whatever the proxy decides.

These statements are valid on PostgreSQL 16 and the sequence name is the one `orders.id` uses, but the resulting privilege set has not been exercised end to end: the development database has no role with `CREATEROLE`, so no restricted role was available to run the suite against. Verify these grants under a genuinely restricted role before relying on them as an enforcement boundary.

## Quick start

Requirements:

- Docker
- Docker Compose

```bash
git clone https://github.com/lihiSabag/SQL-Proxy-Service.git
cd SQL-Proxy-Service
docker compose up --build -d
```

Check that the service is running:

```bash
curl http://localhost:8080/health
```

Expected response:

```json
{"status":"ok"}
```

Run a query:

```bash
curl -X POST http://localhost:8080/query \
  -H "Content-Type: application/json" \
  -d '{"sql":"SELECT id, name, email, phone, credit_card FROM customers ORDER BY id"}'
```

Example masked row:

```json
["1", "Lihi Roas", "l***@example.com", "***0101", "****1111"]
```

Stop the environment:

```bash
docker compose down -v
```

## Testing

The project contains 198 tests:

| Suite | Count |
|---|---:|
| Unit | 152 |
| HTTP contract | 12 |
| PostgreSQL integration and end-to-end | 34 |
| **Total** | **198** |

The test suites cover:

- parser and analyzer contracts;
- policy rule order and rejection reasons;
- real PostgreSQL execution;
- classification and masking invariants;
- structured audit persistence;
- HTTP response behavior;
- the complete production pipeline with a real database.

## Known limitations

- SQL coverage is intentionally bounded by the parser and adapter.
- Some advanced `ALTER TABLE` syntax is unsupported.
- Computed projections that cannot be attributed safely are refused instead of being returned without masking. The canonical `COUNT(*)` is the one recognized exception; `COUNT(1)` and every other variant remain refused.
- Table references hidden inside some subqueries may not be visible to the analyzer.
- Identifier normalization follows a simplified ASCII case model rather than full PostgreSQL identifier semantics.
- Requests are currently processed serially, and each execution opens a short-lived database connection.
- Audit writes are flushed, but host-crash durability through `fsync` is not guaranteed.
- Authentication, authorization, and role-aware policy are not implemented. The audit trail records that an order insert happened, not who requested it, which is a sharper gap for a write than for a read.
- The permitted insert is not idempotent. Submitting it twice creates two orders; duplicate suppression would need a caller-supplied key.
- A quoted `"orders"` cannot be distinguished from the unquoted form, because the parser strips quotes without reporting them. Both resolve to the same relation, so no extra access is granted.
- A statement timeout is currently reported as HTTP 400 together with other execution failures.

### Predicate inference

The proxy prevents direct disclosure of sensitive values in query results. It does not attempt to prevent inference through repeated predicates over sensitive columns.

For example, a caller may learn information from repeated `WHERE` conditions even when the sensitive column is not included in the returned projection.

Production systems usually address this broader threat with complementary controls such as:

- trusted user identity and authorization;
- rate limiting;
- query-pattern monitoring;
- anomaly detection;
- operational alerting;
- predicate-aware access policies.

Output masking alone is not intended to solve this class of inference attack.

## Future work

Potential extensions include:

- broader parser coverage while preserving fail-closed behavior;
- predicate-aware policy enforcement;
- role-aware authorization;
- safe support for selected computed expressions;
- additional PII categories;
- request-level operational metrics;
- connection pooling and concurrent request processing;
- configurable audit durability.