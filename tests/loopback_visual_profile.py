"""Identical fresh-process profiling against before/after Git exports, no network."""

import argparse
import json
import sqlite3
import sys

from tests.production_slimming_profile import no_capture, run


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--active-fixture", action="store_true")
    args = parser.parse_args()
    sys.addaudithook(no_capture)
    queries = 0
    connect = sqlite3.connect

    def trace(_statement):
        nonlocal queries
        queries += 1

    def measured_connect(*args, **kwargs):
        connection = connect(*args, **kwargs)
        connection.set_trace_callback(trace)
        return connection

    sqlite3.connect = measured_connect
    result = run("operator", 3, args.active_fixture)
    result["controller_sqlite_statements_total"] = queries
    result["sql_scope"] = "All controller connections; isolated worker SQL not instrumented"
    print(json.dumps(result))


if __name__ == "__main__":
    main()
