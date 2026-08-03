# SQL Proxy Service

A SQL proxy that will sit between users and PostgreSQL: it receives SQL statements over a small REST
API, analyzes them, enforces an access policy, executes the ones it allows, classifies PII in the
result set, masks it before anything is returned, and records an audit entry for each request.

Written in C++17. Developed on Linux.

This commit contains the service skeleton — configuration, logging, and a health endpoint. The
pipeline stages described below are not implemented yet.

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
