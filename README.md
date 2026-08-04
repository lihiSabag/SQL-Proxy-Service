# SQL Proxy Service

A SQL proxy that will sit between users and PostgreSQL: it receives SQL statements over a small REST
API, analyzes them, enforces an access policy, executes the ones it allows, classifies PII in the
result set, masks it before anything is returned, and records an audit entry for each request.

Written in C++17. Developed on Linux.

The service currently exposes only the health endpoint. The core now includes a tested SQL analysis
component backed by a real SQL parser, and a PostgreSQL execution layer tested against a real
database; neither is connected to the HTTP service yet.

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
# Unit tests — configuration and SQL analysis
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
