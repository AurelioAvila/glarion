#!/usr/bin/env bash
# Manages a throwaway Postgres cluster dedicated to Glarion development.
#
# This is deliberately *not* your system Postgres install: it is a separate
# data directory on a separate port, created and owned by your normal user
# account. Nothing here touches the postgresql-x64-17 service, its data, or
# its configuration — so no superuser password is needed and there is no way
# to damage an existing database.
#
#   bash scripts/dev-db.sh start     # create (first run) and start
#   bash scripts/dev-db.sh stop
#   bash scripts/dev-db.sh status
#   bash scripts/dev-db.sh url       # connection URL for the test database
#   bash scripts/dev-db.sh url dev   # connection URL for the app's database
#   bash scripts/dev-db.sh test      # start, then run the full test suite
#   bash scripts/dev-db.sh destroy   # delete the cluster entirely
#
# The generated password lives in $CLUSTER_DIR/../password, outside the repo.

set -euo pipefail

PORT="${GLARION_DB_PORT:-5433}"
BASE_DIR="${GLARION_DB_HOME:-$HOME/.glarion-devdb}"
CLUSTER_DIR="$BASE_DIR/data"
PASSWORD_FILE="$BASE_DIR/password"
LOG_FILE="$BASE_DIR/postgres.log"

# Two databases on the one cluster, deliberately.
#
# The integration tests TRUNCATE every table. Pointing the running app at
# the same database means a test run silently destroys whatever you were
# working on — accounts, targets, scan history — and the symptom arrives
# much later as "my login stopped working". Keeping them apart costs one
# extra CREATE DATABASE and removes the problem entirely.
TEST_DB_NAME="glarion_test"
DEV_DB_NAME="glarion_dev"
DB_USER="glarion"

find_pg_bin() {
    if command -v initdb >/dev/null 2>&1; then
        return 0
    fi
    for candidate in "/c/Program Files/PostgreSQL"/*/bin; do
        if [ -x "$candidate/initdb.exe" ]; then
            PATH="$candidate:$PATH"
            export PATH
            return 0
        fi
    done
    echo "error: PostgreSQL binaries (initdb) not found." >&2
    echo "Install PostgreSQL, or set PATH to its bin directory." >&2
    exit 1
}

create_cluster() {
    echo "==> Creating a dedicated cluster in $CLUSTER_DIR"
    mkdir -p "$BASE_DIR"

    # A random password for this throwaway cluster. Generated here so no
    # existing credential of yours is involved.
    if [ ! -f "$PASSWORD_FILE" ]; then
        # `head` closing the pipe early makes `tr` exit on SIGPIPE, which
        # `pipefail` would treat as a failure — so this one pipeline opts out.
        (
            set +o pipefail
            LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32 >"$PASSWORD_FILE"
        )
        chmod 600 "$PASSWORD_FILE" 2>/dev/null || true
    fi

    # scram-sha-256 rather than trust: even a local-only dev database
    # should not accept unauthenticated connections from any process on
    # the machine.
    initdb \
        --pgdata="$CLUSTER_DIR" \
        --username="$DB_USER" \
        --pwfile="$PASSWORD_FILE" \
        --auth-host=scram-sha-256 \
        --auth-local=scram-sha-256 \
        --encoding=UTF8 >/dev/null

    # Pin the port in the config rather than passing it via `pg_ctl -o`:
    # the -o form is fragile to quote handling across shells, and baking it
    # in means every later `pg_ctl` invocation agrees on the port.
    cat >>"$CLUSTER_DIR/postgresql.conf" <<EOF

# --- Glarion dev cluster -----------------------------------------------
# Separate port so this never collides with the system PostgreSQL service
# on 5432, and localhost-only so it is unreachable from the network.
port = $PORT
listen_addresses = 'localhost'
EOF

    echo "    created"
}

# Whether the server is genuinely accepting connections.
#
# Deliberately NOT `pg_ctl status`: that only reads postmaster.pid, which
# survives a hard kill of the server process. A stale pid file made this
# script report "already running" and then hand out a URL that nothing was
# listening on. Actually opening a connection is the only honest check.
is_running() {
    pg_isready -h 127.0.0.1 -p "$PORT" >/dev/null 2>&1
}

# Clears a pid file left behind by a server that died without shutting down,
# which would otherwise make pg_ctl refuse to start ("another server might
# be running").
clear_stale_pidfile() {
    if [ -f "$CLUSTER_DIR/postmaster.pid" ] && ! is_running; then
        echo "==> Clearing stale postmaster.pid from a previous unclean exit"
        pg_ctl --pgdata="$CLUSTER_DIR" stop >/dev/null 2>&1 || true
        rm -f "$CLUSTER_DIR/postmaster.pid"
    fi
}

start_cluster() {
    find_pg_bin
    [ -d "$CLUSTER_DIR" ] || create_cluster

    if is_running; then
        echo "==> Already running on port $PORT"
        ensure_databases
        return 0
    fi

    clear_stale_pidfile

    echo "==> Starting cluster on port $PORT"
    # Two Windows/Git Bash details here, both learned the hard way:
    #
    #  * No --wait. It can hold the terminal rather than returning once the
    #    server is up.
    #  * All three standard handles are redirected. The spawned `postgres`
    #    inherits them, so if this script's stdout is a pipe the server
    #    keeps that pipe open forever and anything reading it (a `grep`, a
    #    CI log collector) hangs waiting for EOF that never comes.
    #
    # Port and listen_addresses come from postgresql.conf, written at
    # creation time; server output goes to the log file.
    pg_ctl --pgdata="$CLUSTER_DIR" --log="$LOG_FILE" start >/dev/null 2>&1 </dev/null

    # Poll until it accepts connections rather than sleeping a fixed amount.
    local attempt=0
    until is_running; do
        attempt=$((attempt + 1))
        if [ "$attempt" -gt 30 ]; then
            echo "error: server did not become ready; see $LOG_FILE" >&2
            exit 1
        fi
        sleep 1
    done

    ensure_databases
}

ensure_databases() {
    local password name
    password=$(cat "$PASSWORD_FILE")

    for name in "$TEST_DB_NAME" "$DEV_DB_NAME"; do
        if ! PGPASSWORD="$password" psql -h 127.0.0.1 -p "$PORT" -U "$DB_USER" \
            -d postgres -tAc "select 1 from pg_database where datname = '$name'" \
            | grep -q 1; then
            echo "==> Creating database $name"
            PGPASSWORD="$password" createdb -h 127.0.0.1 -p "$PORT" -U "$DB_USER" "$name"
        fi
    done
}

print_url() {
    local password
    password=$(cat "$PASSWORD_FILE")
    echo "postgres://$DB_USER:$password@127.0.0.1:$PORT/$1"
}

case "${1:-start}" in
    start)
        start_cluster
        echo
        echo "Cluster ready. To run the tests:"
        echo "  bash scripts/dev-db.sh test"
        ;;

    stop)
        find_pg_bin
        pg_ctl --pgdata="$CLUSTER_DIR" --wait stop
        ;;

    status)
        find_pg_bin
        if is_running; then
            echo "running on port $PORT"
        else
            echo "not running"
        fi
        ;;

    url)
        # Defaults to the test database, which is what the test tooling
        # asks for; `url dev` gives the one the running app should use.
        if [ "${2:-test}" = "dev" ]; then
            print_url "$DEV_DB_NAME"
        else
            print_url "$TEST_DB_NAME"
        fi
        ;;

    test)
        start_cluster
        echo
        echo "==> Running the full test suite with integration tests active"
        # --test-threads=1: the integration tests truncate shared tables.
        TEST_DATABASE_URL="$(print_url "$TEST_DB_NAME")" \
            cargo test --workspace -- --test-threads=1
        ;;

    destroy)
        find_pg_bin
        if is_running; then
            pg_ctl --pgdata="$CLUSTER_DIR" --wait stop
        fi
        rm -rf "$BASE_DIR"
        echo "Cluster deleted."
        ;;

    *)
        echo "usage: bash scripts/dev-db.sh {start|stop|status|url [dev]|test|destroy}" >&2
        exit 1
        ;;
esac
