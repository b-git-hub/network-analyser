"""The `run_output` module: the Run folder, `run-report.html` and `audit.log`.

Owns creating and naming the Run folder, the per-user lock, the Run report and the
append-only Audit log, whose writer passes every line through the secret scan. Never
takes raw device output.
"""
