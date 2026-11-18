"""The `device_gateway` module: the single gatekeeper between the tool and any device.

The only module that opens a socket to a device and the only one that imports Netmiko
or Paramiko (security test 3). It checks the Scope where each socket opens, checks the
Trust Store before sending a password, sends every command through one allow-list gate,
drops the session on a config-mode prompt and keeps library session logs off. It hands
back plain device records, never a live session (ADR 0003).
"""
