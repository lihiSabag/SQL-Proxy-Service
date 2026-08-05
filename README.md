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
| Audit Quality | Query outcomes are stored as structured JSON Lines records without SQL text, values, or driver error messages. |
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

Third-party types stay inside the component that owns them: Hyrise inside the SQL parser, libpqxx inside the PostgreSQL executor, and cpp-httplib inside the HTTP layer.

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

This is authorized only when it is the only statement, the unqualified table is exactly `orders`, the explicit columns are exactly `customer_id` then `amount` in that order, the source is `VALUES`, and the two values are a positive integer literal and a positive numeric literal.

Every other write is rejected. A successful insert returns `affected_rows`, policy rejections return a generic `403` so the rule set cannot be mapped by probing, and database failures are sanitized before they reach the caller.

### Classification logic

A sensitive column must not be treated as safe simply because its source cannot be determined. Classification combines the analyzed SELECT projection, the column metadata returned by PostgreSQL, and a configurable case-insensitive mapping of known PII column names. The classifier receives column metadata only. It never inspects row values, so sensitive values cannot enter or leak from it.

Each result column receives one of three states: `Pii`, `NotClassifiedAsPii`, or `Unattributed`. `Unattributed` is intentionally distinct from non-PII, because treating an unknown column as safe is exactly the bug that would release unmasked data.

The supported PII categories are `PII.Email`, `PII.Phone`, and `PII.CreditCard`.

The canonical `COUNT(*)` is the single computed projection recognized as safe: it counts rows rather than reading column contents, so it has no lineage to a stored value. Other computed projections, and every other `COUNT` variant, are refused when they cannot be attributed safely.

The trade-off is that metadata-based classification is predictable and testable, but cannot identify sensitive data stored under a misleading column name.

### Masking enforcement

Masking runs after execution and classification, using the actual result-column order, and always before any result leaves the service:

```text
lihi.roas@example.com -> l***@example.com
0501230101            -> ***0101
4111111111111111      -> ****1111
```

The same category always follows the same rule. `NULL` stays `NULL` and an empty string stays empty: masking transforms values, it does not invent them.

Before changing any cell, the masker validates the complete classification and result shape. If any column is unattributed or the shapes do not line up, the whole result is refused rather than partially masked.

### Audit quality

An audit trail should record request outcomes without becoming another source of sensitive-data leakage. Every request handled by the SQL pipeline produces one JSON Lines record:

```json
{"timestamp":"2026-08-05T09:16:05.842Z","request_id":1,"outcome":"SUCCESS","statement_type":"SELECT","referenced_tables":["customers"],"row_count":2,"column_count":5,"pii_email_columns":1,"pii_phone_columns":1,"pii_credit_card_columns":1}
```

Records use closed enums and numeric fields. They exclude raw SQL, query values and literals, column names and aliases, result values, database error messages, connection strings, and file paths.

Safe referenced table names may be recorded. A name is kept only if it is a plain unqualified ASCII identifier within a length and count limit; if any name fails, the whole list is dropped and the record carries `referenced_tables_omitted` instead. Names are never truncated, and parsing and internal failures carry no table metadata at all.

A successful result is not returned if its audit record cannot be persisted.

### System log

The system log is separate from the audit trail. It records operational events such as startup and configuration, the HTTP listening port, startup failures, and audit persistence failures. It never logs SQL, identifiers, values, or database error text.

## Data setup

`sql/schema.sql` and `sql/seed.sql` create and populate `customers` and `orders`. All values are fabricated and chosen to demonstrate masking, classification, and policy outcomes, including `NULL` and empty-string handling and both card lengths.

## Run

```bash
docker compose up --build -d

curl -s -X POST http://localhost:8080/query \
  -H "Content-Type: application/json" \
  -d '{"sql":"SELECT id, name, email FROM customers ORDER BY id"}'
```

Rows come back as positional arrays with PII already masked, for example
`["1", "Lihi Roas", "l***@example.com"]`. Stop with `docker compose down -v`.

## Testing

276 tests: 212 unit, 13 HTTP contract, and 51 PostgreSQL integration and end-to-end. They cover parser and analyzer contracts, policy rule order and rejection reasons, real PostgreSQL execution, classification and masking invariants, structured audit persistence, HTTP response behavior, and the complete production pipeline against a real database.

## Design notes

Production deployments should also use a least-privilege PostgreSQL role.

## Known limitations

- SQL coverage is intentionally bounded by the parser and the analysis model.
- Computed projections that cannot be attributed safely are refused rather than returned unmasked. The canonical `COUNT(*)` is the one exception.
- Table references hidden inside some subqueries may not be visible to the analyzer.
- Identifier normalization follows a simplified ASCII case model rather than full PostgreSQL identifier semantics.
- Requests are processed serially, and each execution opens a short-lived database connection.
- Authentication, authorization, and role-aware policy are not implemented, so the audit trail records what happened but not who requested it.
- Output masking prevents direct disclosure of sensitive values, but it does not prevent inference through repeated predicates. Production systems need complementary controls such as authorization, rate limiting, and monitoring.
