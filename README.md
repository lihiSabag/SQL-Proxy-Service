# SQL Proxy Service

A SQL proxy that will sit between users and PostgreSQL: it receives SQL statements over a small REST
API, analyzes them, enforces an access policy, executes the ones it allows, classifies PII in the
result set, masks it before anything is returned, and records an audit entry for each request.

Written in C++17. Developed on Linux.

The pipeline is now wired end to end: `POST /query` analyzes the statement, applies the read-only
policy, executes what it allows against PostgreSQL, classifies and masks PII in the result, and
records the outcome in the audit trail before responding.

## Request pipeline

```
HTTP request
  → SQL analysis      (statement type, tables, projection)
  → policy            (allow / reject, with a reason)
  → execution         (run the allowed statement)
  → classification    (which result columns carry PII)
  → masking           (transform those values)
  → audit             (record the outcome)
  → HTTP response
```

## SQL analysis

`SqlAnalyzer` converts structured parser output into a parser-independent `SqlAnalysis`. It records
the statement type and class, statement count, referenced tables, projection columns, wildcard and
computed-projection flags, and features it could not model.

The analyzer depends on the `ISqlParser` interface rather than a specific parser library.

## SQL parsing

Parsing uses [`hyrise/sql-parser`](https://github.com/hyrise/sql-parser), pinned to a specific
commit and vendored through CMake `FetchContent`. It gives a real AST for the statement types
supported by the proxy — `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `CREATE`, `ALTER`, `DROP` — and it
reports multi-statement input, which a proxy has to be able to see. It ships pre-generated parser
and lexer sources, so **the parser itself needs no bison or flex**.

The parser sits behind the `ISqlParser` interface, and `HyriseSqlParser` is the only place `hsql::`
types appear. Everything downstream, starting with `SqlAnalyzer`, sees only the project's own
`ParsedStatement`, so the parser library can be swapped without touching the analysis, and the
analyzer can be tested against a hand-written fake.

**Parse errors are sanitized.** A rejected statement produces an error built only from fixed text
plus a line and column number — never the parser's own message, and never a fragment of the
submitted SQL. A test forces a syntax error on input containing a distinctive literal and asserts
the literal does not appear in the error.

**Analysis is best-effort, and the design assumes that.** Where the analyzer knows its picture is
incomplete, it reports that explicitly so later stages can decide how to handle it. Known
limitations:

- `ALTER TABLE … ADD COLUMN` does not parse (the parser supports `DROP COLUMN` only). Unsupported
  ALTER syntax becomes a sanitized parse error.
- Identifier case is preserved exactly as parsed. The parser neither case-folds unquoted
  identifiers nor reports whether an identifier was quoted, so PostgreSQL-accurate case
  normalization is impossible here.
- Tables referenced only inside a `WHERE`-clause or projection subquery are invisible to the table
  list. CTEs, set operations and `FROM`-subqueries are flagged as unsupported features.
- `SELECT … FOR UPDATE` parses as a plain `SELECT`; the locking clause is not surfaced.
- Statements outside the supported set (for example `SHOW`) parse successfully but map to the
  `Unknown` statement type.

## Access policy

**The proxy is intentionally read-only: only `SELECT` is allowed.** Supporting write operations would
require additional authorization semantics, broader audit rules, and handling write-specific SQL
constructs. Those concerns are outside the current design.

`PolicyEngine` consumes only a `SqlAnalysis` and returns a `PolicyDecision`: an `allowed` flag plus a
typed `RejectReason`. The reason is an enum, never a string, so a decision cannot carry SQL text,
identifiers, or data values. Defaults are fail-closed — a decision that was never evaluated reads as
rejected.

The rule set is evaluated in a fixed order, first match wins:

| # | Condition | Rejection reason |
|---|---|---|
| 1–3 | empty input · unparseable · multiple statements | `EMPTY_INPUT` · `UNPARSEABLE_SQL` · `MULTIPLE_STATEMENTS` |
| 4 | analysis reports "ok" but not exactly one statement | `MULTIPLE_STATEMENTS` (defensive) |
| 5 | statement type outside the supported seven (`COPY`, `SHOW`, `BEGIN`, …) | `UNSUPPORTED_STATEMENT_TYPE` |
| 6–7 | DDL · DML | `DDL_NOT_ALLOWED` · `DML_NOT_ALLOWED` |
| 8 | analyzer flagged an unsupported feature | `UNSUPPORTED_SQL_FEATURE` |
| 9 | `pg_catalog.*`, `information_schema.*`, or a `pg_*` table | `SYSTEM_TABLE_ACCESS` |
| 10 | `SELECT *, col …` — mixed wildcard and explicit projection | `UNATTRIBUTABLE_PROJECTION` |
| 11 | otherwise: exactly one analyzed `SELECT` | **allowed** |

Rules 6 and 7 cover more than they appear to. `TRUNCATE` parses as an ordinary `DELETE`, so the DML
rule is what keeps it out, and `CREATE TABLE … AS SELECT` parses as `CREATE`, so the DDL rule catches
it.

Rules 3 and 4 are what uphold the executor's precondition that it receives exactly one approved
statement — the executor deliberately never counts or splits SQL itself.

Rule 8 comes before rule 9 on purpose: the catalog scan should only ever run against a table list the
analyzer vouches for. If analysis is known to be incomplete, the request is rejected rather than
checked against a list that may be missing entries.

Rule 9 is **defense in depth, not a boundary**. It blocks direct catalog probes (`pg_authid`,
`pg_stat_activity`, `information_schema`), which is most real-world catalog snooping, but a subquery
can hide a reference the analyzer never sees. Matching is case-insensitive, because PostgreSQL folds
unquoted identifiers while the parser preserves spelling. **The real enforcement boundary is
PostgreSQL's own permission system**: run the service under a least-privilege, read-only role that
has `SELECT` on exactly the tables it should read and nothing else.

Rule 10 exists because `SELECT *, credit_card AS x FROM customers` defeats *both* ways of attributing
a result column to its source: the star breaks positional alignment, and the alias breaks name
lookup. The aliased column would otherwise reach the caller unclassified, so the request is rejected
before it runs. See [Data classification](#data-classification) for the two attribution modes.

Rule 11 is deliberately permissive about projection shape: plain columns, aliases, wildcards,
computed projections and table-less selects are all allowed. General computed projections
(`UPPER(email)`, `COUNT(*)`) are **not** rejected by policy — the classifier marks them
`Unattributed` instead.

The engine is a pure function of its input — it never sees raw SQL text, execution results, or an
identity, and it performs no authentication, no roles, and no per-user rules.

## Query execution

`IQueryExecutor` is the port that runs an approved statement; `PostgresQueryExecutor` implements it
over `libpqxx`. It executes the exact SQL text it is given — never a reconstructed query — and
returns a database-neutral `ExecutionResult`: column names with a project-owned `ColumnType`, cells
as `std::optional<std::string>` so SQL `NULL` and the empty string stay distinct, plus row and
affected-row counts.

Each call opens one connection and runs one transaction, committed only on success; any other path
unwinds and the transaction aborts. `pqxx` types and exceptions never leave the adapter — every
failure comes back as an `ExecutionStatus` of `ConnectionFailure` or `ExecutionFailure`, which is
also the default, so a partially populated result is a failure rather than a silent success.

**Database errors are sanitized.** PostgreSQL messages routinely echo data values, and connection
errors can echo connection details, so the returned error is assembled only from fixed text plus at
most a five-character SQLSTATE code — never driver text, SQL fragments, or the connection string.
Tests force a syntax error and a unique-violation carrying a distinctive literal and assert that
neither the literal nor any statement fragment appears in the error.

## Data classification

`DataClassifier` decides **what each result column carries**, not what to do about it. It produces a
`ClassificationResult` with exactly one entry per result column, in result-column order.

Classification is **metadata- and mapping-based**. The classifier receives the SQL analysis and the
result set's *column metadata* — never a single cell value, never a row. Because no data enters it,
no data can leak from it, and its unit tests construct nothing but an analysis and a column list.

A small configured map drives it: `email → PII.Email`, `phone → PII.Phone`,
`credit_card → PII.CreditCard`, matched case-insensitively. The map is constructor-injectable, so a
differently named column can be classified without touching the schema. A config whose keys collide
after normalization is refused at construction rather than silently resolved to one of them.

Each column ends up in one of three states — three, deliberately, not two:

| State | Meaning |
|---|---|
| `NotClassifiedAsPii` | examined, and not sensitive under the configured mapping |
| `Pii` | carries one of the three categories |
| `Unattributed` | **could not determine** what this column carries |

`Unattributed` is the fail-closed default, and `fully_attributed` is false whenever any column holds
it. Collapsing "not sensitive" into "unknown" is exactly the bug that would let unidentified data
flow onward as if it had been checked.

Two attribution modes:

- **Positional** (plain or aliased explicit projections): result column *i* is attributed to
  projection column *i*, with any qualifier stripped — `customers.email` and `c.email` both look up
  `email`. This is what makes aliases useless as an evasion: `SELECT email AS contact` is still
  classified from `email`, not from the result name `contact`.
- **Wildcard** (`SELECT *` alone): the database returns the true source column names, so name lookup
  is exact.

Everything else — computed projections, projection/result count mismatches, and any analysis that is
not a single successful `SELECT` — yields all columns `Unattributed`. The classifier never guesses a
source column, never shifts indices, never classifies a partial prefix, and never quietly downgrades
an unknown column to "not sensitive".

Two details worth stating:

- **Duplicate result column names are safe.** A join can produce two columns both named `email`;
  classifications are stored **by index**, never in a name-keyed map that would collapse them.
- **Joins are handled by column name only.** A qualifier in a projection is a table *alias* the
  analysis cannot resolve back to a real table, so it is stripped and the bare column name is looked
  up. Column-name-only mappings over-classify at worst, which is the safe direction.

Policy rule 10 removes the one shape that would otherwise be ambiguous in a dangerous way — mixed
wildcard and explicit projection — before execution. General computed projections are still allowed
by policy and simply classify as `Unattributed`; what a later stage does with an unattributed column
is not decided here.

**Why not detect PII by inspecting values?** A regex scanner is wrong in both directions: a 16-digit
order reference matches a card pattern, an unusually formatted phone number matches nothing, and
per-row verdicts make column-level decisions incoherent (treat the column as sensitive because row 3
matched?). Real products do value scanning with trained detectors, validators and review workflows; a
quick regex imitates the feature while faking its reliability. The cost of this choice is real and
stated plainly: **PII in an unmapped or misleadingly named column is invisible** — metadata-based
classification cannot see that a `notes` column contains card numbers.

Classification decides *what* a column is; masking decides how it is transformed.

## PII masking

`PiiMasker` transforms values **only** according to the classification it is given. It never
re-classifies; a value is inspected solely to apply the already-chosen transformation, so a `notes`
column containing an email address is returned untouched.

| Category | Rule | Example |
|---|---|---|
| `PII.Email` | keep the first character and the domain | `lihi.roas@example.com` → `l***@example.com` |
| `PII.Phone` | 7+ digits → `***` + last four, formatting discarded | `0501230101` → `***0101` |
| `PII.CreditCard` | 12+ digits → `****` + last four | `4111111111111111` → `****1111` |

Across all three: **`NULL` stays `NULL`** and **`""` stays `""`** — masking transforms values, it
does not fabricate them; turning a `NULL` card into `***` would assert that a customer has a card
when the truthful answer is "none recorded". Every other non-empty value **always changes**; anything
malformed falls back to `***` rather than passing through.

Two deliberate trade-offs:

- **The email domain is preserved.** `l***@example.com` is the industry-familiar format and keeps
  output readable, but a domain can identify a person at a small organization. Masking the domain as
  well is a one-line change if that risk matters more than legibility.
- **Phones are masked partially.** The last four digits are what a support workflow realistically
  needs; full redaction is the alternative.

Card numbers are masked to a uniform width, so a 15-digit Amex and a 16-digit Visa are
indistinguishable in the output — the masked form leaks neither length nor network. There is no Luhn
check: validating a value would be classification by another name, and classification is already
settled by then.

**A masking call either returns a fully masked result or no result at all.** `MaskingOutcome` is
success-or-failure by type: a failure cannot carry a result, so partially masked data is not
representable. It cannot be default-constructed either — a default would masquerade as a success the
masker never produced. Reading the wrong side of an outcome throws rather than returning something
plausible.

Masking runs in two phases. Phase one validates everything — column counts, every row's width, the
classification invariants — before a single cell is touched. Phase two is total for validated input:
it works by column **index**, so duplicate column names are irrelevant, and column order, row order,
result shape and column metadata all pass through unchanged.

An `Unattributed` column is refused, not redacted:

| Failure | Meaning |
|---|---|
| `UNATTRIBUTED_COLUMN` | classification could not account for every column — the expected fail-closed outcome |
| `STRUCTURAL_MISMATCH` | shapes do not line up |
| `INVALID_CLASSIFICATION` | classification invariants are broken |

Refusing rather than blanket-redacting is deliberate: a column nobody could identify should not be
returned at all, and it should not be *value*-inspected in a last-minute attempt to identify it.

Two properties worth stating plainly. The masker contains **no logging** — it is the one component
guaranteed to hold raw PII. And **idempotence is not claimed**: there is no already-masked detection,
because the pipeline invariant is that masking happens exactly once.

## Audit trail

An `AuditRecord` describes one controlled request outcome. Records are written as one JSON object per
line — JSON Lines — through the `IAuditRepository` port, implemented by `JsonlAuditRepository`:

```json
{"column_count":5,"outcome":"SUCCESS","pii_credit_card_columns":1,"pii_email_columns":1,"pii_phone_columns":1,"request_id":1,"row_count":4,"statement_type":"SELECT","timestamp":"2026-08-04T09:23:33.265Z"}
{"outcome":"POLICY_REJECTED","reason":"DDL_NOT_ALLOWED","request_id":2,"statement_count":1,"statement_type":"DROP","timestamp":"2026-08-04T09:23:45.419Z"}
{"outcome":"PARSING_FAILURE","request_id":3,"timestamp":"2026-08-04T09:23:45.424Z"}
{"column_count":1,"outcome":"MASKING_REFUSED","request_id":5,"statement_type":"SELECT","timestamp":"2026-08-04T09:23:45.433Z"}
{"category":"EXECUTION_FAILURE","outcome":"DATABASE_FAILURE","request_id":6,"statement_type":"SELECT","timestamp":"2026-08-04T09:23:45.454Z"}
```

**What is recorded, and why it is enough.** The questions an auditor actually asks are *what kind of
statement was this, what did we decide, how much data was exposed, and was it masked* — so each
record carries a UTC timestamp, a request id, the outcome, the statement type, and outcome-specific
counts: rows and columns returned, and how many result **columns** (not cells) fell into each PII
category. `SUCCESS` implies masking completed; `MASKING_REFUSED` implies it did not. Those facts are
derived from the outcome rather than stored, so a record cannot contradict itself — the outcome is
read from which detail alternative is present, and there is no separate field to disagree with it.

**What is deliberately *not* recorded, and why.** No SQL text — raw, normalized, or hashed. No result
values, masked or otherwise. No column, alias, table or schema names. No database or exception
messages. No file paths, credentials, or connection strings. No user identity.

This is the security decision the audit design turns on. **SQL text routinely embeds the very data
the proxy exists to protect** — `WHERE email = 'lihi.roas@example.com'` would put PII into the audit
log permanently, in a file that outlives the request and is read by more people than the result ever
was. A hash does not fix it either: hashing preserves equality, so records become joinable by query,
and short predictable statements fall to a dictionary attack that reconstructs the text.

The guarantee is structural, not procedural: `AuditRecord` **has no free-form string field**. Its
members are enums, integers and a timestamp, so SQL, values and names are not "filtered out" — they
are unrepresentable. Even the failure vocabulary is a closed enum, so an I/O error cannot smuggle a
path or an `errno` string into the trail.

A record cannot be default-constructed; each outcome has its own factory, and the factories refuse
combinations that would misdescribe the event: a parse failure is audited only as `PARSING_FAILURE`
and never duplicated as a policy rejection, and outcomes reachable only for `SELECT` under the
read-only policy insist on it. Reading the wrong detail type throws rather than returning something
plausible.

PII category counts are recorded **only for `SUCCESS`**. When masking is refused the classification
was incomplete by definition, and a count such as `pii_email_columns: 0` for
`SELECT CONCAT(name, email) …` would be precise, closed-vocabulary, and *misleading*.

The JSONL adapter is the only place `nlohmann::json` appears in this part of the system. Objects are
built through the JSON library rather than by string concatenation, field names are compile-time
literals, enum values come from the closed `to_string` tables, and **inapplicable fields are omitted
entirely** rather than written as null or zero placeholders. Timestamps are formatted as
deterministic ISO-8601 UTC with milliseconds, in the adapter, so the core record model stays free of
presentation concerns.

**Durability, stated honestly.** Each record is written and flushed to the OS on append, and an
instance mutex prevents interleaving between threads in one process. There is no `fsync`, no
multi-process locking, and no recovery from a crash mid-write — a hard kill can cost the trailing
line. The file is opened in append mode, created if missing, and never read back, so existing
contents are preserved and malformed pre-existing lines never block new appends. Failures are
reported as `OPEN_FAILURE` or `WRITE_FAILURE`, with no path and no OS text, and are not retried.

**Audit is not application logging.** The system log narrates operations for whoever is running the
service; the audit trail records outcomes for later review. Different audiences, different rules,
different destinations.

**Every controlled SQL request produces exactly one audit append attempt** — success, rejection or
failure alike. That is structural: the orchestrator's internal step returns a client result and an
audit record together, from every path, and there is exactly one call site that appends.

## Prerequisites

Developed on **Ubuntu 24.04, g++ 13, CMake 3.28, PostgreSQL 16**.

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake git curl zip unzip tar \
                        pkg-config autoconf libtool bison flex \
                        postgresql postgresql-client
```

`bison` and `flex` are listed for vcpkg, not for the SQL parser: `hyrise/sql-parser` ships
pre-generated sources and needs neither, but vcpkg may need both when it builds the
PostgreSQL/`libpq` chain from source on a fresh machine. Both are build-time only — neither is a
runtime dependency, and neither is linked into the service.

Dependencies come from vcpkg in manifest mode (`vcpkg.json`):

```bash
git clone https://github.com/microsoft/vcpkg ~/vcpkg && ~/vcpkg/bootstrap-vcpkg.sh
```

`hyrise/sql-parser` is fetched by CMake at a pinned commit; it is not a vcpkg dependency.

## Build

```bash
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE="$HOME/vcpkg/scripts/buildsystems/vcpkg.cmake"
cmake --build build -j
```

The first configure builds the dependencies from source and takes a while; later builds are fast.

Produces `build/sql_proxy_service`, `build/sql_proxy_unit_tests`,
`build/sql_proxy_http_tests` and `build/sql_proxy_integration_tests`.

## Database setup

Create a role and database, then apply the schema and seed data:

```bash
sudo -u postgres psql <<'SQL'
CREATE ROLE sql_proxy_user LOGIN PASSWORD 'change-me';
CREATE DATABASE sql_proxy OWNER sql_proxy_user;
SQL

psql "postgresql://sql_proxy_user@localhost:5432/sql_proxy" -f sql/schema.sql
psql "postgresql://sql_proxy_user@localhost:5432/sql_proxy" -f sql/seed.sql
```

`sql/schema.sql` creates two tables and **drops only those two** — never a database or schema:

| Table | Columns |
|---|---|
| `customers` | `id`, `name`, `email`, `phone`, `credit_card` |
| `orders` | `id`, `customer_id` → `customers(id)`, `amount`, `created_at` |

`sql/seed.sql` inserts four customers and four orders. All values are fabricated, and the coverage
is deliberate: two normal phone numbers, one `NULL` phone and one empty-string phone (so the NULL vs
`""` distinction is demonstrable), and card numbers in two lengths.

> **All stored credit-card numbers are synthetic test values** — the publicly published
> non-transactable test numbers (`4111…`, `5555…`, `3782…`). No real cardholder data is present
> anywhere in this repository.

For least privilege, grant the service role only what it needs. The proxy is intended to run under a
**read-only** role: its own checks are best-effort, and database permissions are the boundary that
actually holds.

```sql
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM sql_proxy_user;
GRANT SELECT ON customers, orders TO sql_proxy_user;
```

## Configuration

All configuration is environment variables. Errors name the variable, never its value.

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `PORT` | no | `8080` | HTTP listen port |
| `DATABASE_URL` | **yes** | — | libpq connection URI. Treated as a secret: never logged, never returned in an error, never printed by tests. |
| `DB_STATEMENT_TIMEOUT_MS` | no | `5000` | per-statement timeout, applied as `SET LOCAL statement_timeout`; must be a positive integer up to 600000 |
| `AUDIT_LOG_PATH` | no | `audit.jsonl` | JSON Lines audit sink |

Startup fails fast with a clear message and exit code 1 if `DATABASE_URL` is missing or another value
is invalid. Errors name the variable, never its value.

**Keep the password out of `DATABASE_URL`.** Put it in `~/.pgpass` (mode `600`) and omit it from the
URL, so it never appears in your shell history, the process list, or the environment:

```
localhost:5432:sql_proxy:sql_proxy_user:change-me
```
```bash
export DATABASE_URL="postgresql://sql_proxy_user@localhost:5432/sql_proxy"
```

## Running

```bash
export DATABASE_URL="postgresql://sql_proxy_user@localhost:5432/sql_proxy"
export AUDIT_LOG_PATH="./audit.jsonl"
./build/sql_proxy_service
```

Stop with `Ctrl-C` / `SIGTERM`.

## API

### `GET /health`

```console
$ curl -s localhost:8080/health
{"status":"ok"}
```

### `POST /query`

```console
$ curl -s -XPOST localhost:8080/query -H 'Content-Type: application/json' \
       -d '{"sql":"SELECT id, name, email FROM customers ORDER BY id"}'
{"columns":["id","name","email"],
 "row_count":4,
 "rows":[["1","Lihi Roas","l***@example.com"],
         ["2","Kim Perez","k***@example.org"],
         ["3","Daniel Mizrahi","d***@example.net"],
         ["4","Yael Azulay","y***@example.com"]]}
```

Rows are **positional arrays**, not objects: column order is preserved and duplicate column names
(`SELECT email, email …`) both survive, which a JSON object would silently collapse. SQL `NULL`
becomes JSON `null` and an empty string stays `""`. Column metadata is returned even when there are
zero rows.

Failures return `{"error":"<code>","message":"<fixed text>"}` and never contain SQL, values, column
or table names, SQLSTATE codes, or driver text:

| Situation | Status | `error` |
|---|---|---|
| bad content type, invalid JSON, missing/non-string `sql`, body over 64 KiB | `400` | `bad_request` |
| empty `sql` | `400` | `empty_sql` |
| SQL could not be parsed | `400` | `invalid_sql` |
| rejected by policy (any reason) | `403` | `policy_rejected` |
| the database rejected the statement | `400` | `query_failed` |
| the database was unreachable | `503` | `database_unavailable` |
| results could not be safely masked | `422` | `masking_refused` |
| internal error, including an audit write failure on an otherwise successful request | `500` | `internal_error` |

**Every policy denial returns the same generic `403`.** The audit record keeps the precise reason;
the client cannot tell a system-catalog rejection from a DML rejection, so the rule set cannot be
mapped by probing. The transport-level `400`s are the exception in another sense: they are rejected
before the pipeline runs and produce **no** audit record, because they are malformed HTTP requests
rather than SQL requests.

## Concurrency model

`ProxyService` serializes the entire pipeline behind one mutex: **one controlled SQL request is
processed at a time.** The executor itself is safe to call concurrently — it holds no shared mutable
state and opens a connection per call — but without a connection pool, N concurrent requests would
open N simultaneous database connections with no upper bound. Serializing bounds that to one and
keeps behaviour deterministic. Throughput is explicitly out of scope; a connection pool behind
`IQueryExecutor` plus removing this lock is the documented next step, and it touches no core
contract.

## Testing

Three executables. The first two need no database and never skip.

```bash
# Unit tests — configuration, analysis, policy, classification, masking, audit, orchestration
./build/sql_proxy_unit_tests

# HTTP contract tests — request/response shapes, status codes, leak assertions
./build/sql_proxy_http_tests

# Executor + end-to-end tests — REQUIRE a real PostgreSQL (see below)
export TEST_DATABASE_URL="postgresql://sql_proxy_test_user@localhost:5432/sql_proxy_test"
SQL_PROXY_TEST_DB_RESET=1 ./build/sql_proxy_integration_tests

(cd build && ctest -L unit)     # or -L http, -L postgres, or ctest for everything
```

The database-backed tests are **fail-closed by design**, because they drop and recreate the demo
tables:

1. `TEST_DATABASE_URL` must name the dedicated database `sql_proxy_test`. Any other name is a hard
   failure with **zero SQL executed** — pointing the suite at a real database cannot cause writes.
2. Destructive setup additionally requires `SQL_PROXY_TEST_DB_RESET=1`. Without it the suite skips.

A skipped run is never counted as verification. Set up the dedicated test database once:

```bash
sudo -u postgres psql <<'SQL'
CREATE ROLE sql_proxy_test_user LOGIN PASSWORD 'test-only';
CREATE DATABASE sql_proxy_test OWNER sql_proxy_test_user;
SQL
```

The executor tests write to their own tables, so this database must be separate from the one the
service runs against.

### End-to-end tests

The end-to-end suite drives the **real** pipeline — real parser, real analysis, real policy, real
PostgreSQL executor, real classifier, masker and JSONL audit — through the actual HTTP handler, with
no fakes anywhere. Each test gets its own temporary directory and audit file and issues one request,
so nothing carries between tests; both suites reset the schema and seed data at their first test, so
neither depends on leftover database state or on running in a particular order.

Every masked value is asserted exactly against the seeded data, including `NULL` versus the empty
string and both card lengths. Audit lines are checked **structurally**, not by substring search: each
line is parsed, its key set must match the closed schema for its outcome, forbidden keys must be
absent, and every string value must be either a shape-checked UTC timestamp or a closed-vocabulary
enum value. A substring sweep would be useless here, since legitimate audit content contains the
strings `SELECT` and `pii_email_columns`.

The end-to-end tests do not exercise `main.cpp`'s process wiring — configuration resolution,
component construction and signal handling. Running the built binary directly covers that.

## Known limitations

- **A database execution failure returns `400`.** That is right for a genuinely malformed statement,
  but a statement timeout is a server-side condition reported to the caller as if the request were at
  fault. Distinguishing them would mean a coarse typed category from the executor, never a raw
  SQLSTATE.
- **Computed projections are refused, not masked.** `SELECT UPPER(email) …` and, as collateral,
  `SELECT COUNT(*) …` and `SELECT 1` return `422`. The parser does not preserve the source column of
  an expression, so the result column can be attributed by neither name nor position, and returning it
  unmasked is not acceptable. Refusing is the fail-closed choice; the aggregate case is a real cost.
- **PII in an unmapped or misleadingly named column is invisible** (see
  [Data classification](#data-classification)).
- **One request at a time** (see [Concurrency model](#concurrency-model)).
- **Audit durability is process-level**, not crash-safe (see [Audit trail](#audit-trail)).
