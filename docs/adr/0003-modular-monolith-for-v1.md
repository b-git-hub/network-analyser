# Modular monolith for v1; containers and microservices deferred

_v1 ships unsigned. Signing was deferred on [Release pipeline, signing and versioning](https://github.com/b-git-hub/network-analyser/issues/32) until the unsigned build is blocked on the operator's PC or the tool is handed to anyone else, and the proper-deployment phase signs by default. Where this ADR says "signed", that is the later goal, not v1._

v1 is one Windows program: a single process, built from internal modules and shipped as a signed PyInstaller one-folder build in a zip. It is not a Docker container or a set of microservices. One operator runs it on demand on Windows with no Python install. Docker on Windows needs Docker Desktop, WSL2 and admin rights to install. Microservices would send Credential Set passwords between processes, so both add cost and attack surface v1 does not need. They are **deferred, not rejected**: the operator is open to a containerised or microservice deployment in a phase 2, provided passwords passed between parts can be secured.

Decided on [Architecture and packaging: modular monolith exe vs Docker or microservices](https://github.com/b-git-hub/network-analyser/issues/9).

## Consequences

- **One gatekeeper.** `device_gateway` is the only module that opens a connection to a device. It checks the Scope before connecting and the Trust Store before sending a password, sends only allow-listed commands, and keeps library session logs off. It is the only module that imports Netmiko or Paramiko, and a test enforces this.
- **Passwords stay in two modules.** Only `credentials` and `device_gateway` ever hold a password, and only in memory.
- **Platforms are built in.** IOS/IOS-XE and NX-OS support is part of the exe. Nothing is loaded from a plugins folder at run time, so a new Platform means a new release.
- **Plain data between modules.** Modules pass simple records, not live sessions or shared objects. Any boundary, most likely `device_gateway`, can then become a separate service in phase 2 without a redesign. v1 builds no queues, RPC or sockets between parts.
- **Topology file.** The Topology is saved as a plaintext, redacted JSON file, and the diagram is drawn only from that file. `render` can redraw a diagram without logging into any device.
- **One-folder build.** The tool ships as a one-folder build, not a self-extracting single file. It starts faster, gets fewer antivirus false positives, never unpacks code into `%TEMP%`, and leaves the LGPL Paramiko replaceable.
- **No admin rights.** The tool runs as a standard user and warns if it is run elevated.

## Considered Options

- **Docker container:** needs Docker Desktop and WSL2 on the operator's Windows machine, and a paid licence in larger organisations. Deferred to phase 2.
- **Microservices:** passwords would cross process and network boundaries. Deferred to phase 2, when that can be secured.
- **PyInstaller one-file exe:** slower to start, flagged by antivirus more often, and unpacks to a temp folder on every start.
