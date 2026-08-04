# SQL Proxy Service

A SQL proxy that will sit between users and PostgreSQL: it receives SQL statements over a small REST
API, analyzes them, enforces an access policy, executes the ones it allows, classifies PII in the
result set, masks it before anything is returned, and records an audit entry for each request.

Written in C++17. Developed on Linux.

The service currently exposes only the health endpoint. The core now includes a tested SQL analysis
component backed by a real SQL parser; it is not connected to the HTTP service yet.

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
and lexer sources, so **bison/flex are not needed to build it**.

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

## Prerequisites

Developed on **Ubuntu 24.04, g++ 13, CMake 3.28**.

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake git curl zip unzip tar \
                        pkg-config autoconf libtool
```

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

Produces `build/sql_proxy_service` and `build/sql_proxy_unit_tests`.

## Configuration

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `PORT` | no | `8080` | HTTP listen port |

An invalid value fails at startup with a clear message and exit code 1.

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

```bash
./build/sql_proxy_unit_tests
(cd build && ctest -L unit)
```
