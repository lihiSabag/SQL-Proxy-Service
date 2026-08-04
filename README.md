# SQL Proxy Service

A SQL proxy that will sit between users and PostgreSQL: it receives SQL statements over a small REST
API, analyzes them, enforces an access policy, executes the ones it allows, classifies PII in the
result set, masks it before anything is returned, and records an audit entry for each request.

Written in C++17. Developed on Linux.

The service currently exposes only the health endpoint. The core now includes a tested SQL analysis
component backed by a real SQL parser, a read-only access policy, a PostgreSQL execution layer tested
against a real database, and PII classification of result columns; none of them is connected to the
HTTP service yet.

## Planned request pipeline

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

Masking is not implemented yet. Classification decides *what* a column is; transforming values is a
separate step, still to come.

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

Produces `build/sql_proxy_service`, `build/sql_proxy_unit_tests` and
`build/sql_proxy_integration_tests`.

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
| `DATABASE_URL` | yes, for the execution layer | — | libpq connection URI. Treated as a secret: never logged, never returned in an error, never printed by tests. |
| `DB_STATEMENT_TIMEOUT_MS` | no | `5000` | per-statement timeout, applied as `SET LOCAL statement_timeout`; must be a positive integer up to 600000 |

An invalid value fails with a clear message that names the variable only.

`DATABASE_URL` is read by the execution layer, which the HTTP service does not use yet, so
`./build/sql_proxy_service` still starts without it.

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
./build/sql_proxy_service
```

Stop with `Ctrl-C` / `SIGTERM`.

## API

### `GET /health`

```console
$ curl -s localhost:8080/health
{"status":"ok"}
```

## Testing

Two executables. The unit tests need no database and never skip.

```bash
# Unit tests — configuration, SQL analysis, policy and classification
./build/sql_proxy_unit_tests

# Executor tests — REQUIRE a real PostgreSQL (see below)
export TEST_DATABASE_URL="postgresql://sql_proxy_test_user@localhost:5432/sql_proxy_test"
SQL_PROXY_TEST_DB_RESET=1 ./build/sql_proxy_integration_tests

(cd build && ctest -L unit)     # or -L postgres, or ctest for everything
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
