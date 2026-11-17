# Network Analyser

An operator-run tool that discovers the network devices inside a set of IP ranges, backs up their running configuration, and draws how they connect.

## Discovery

**Scope**:
The set of IP ranges the operator gives for a Run. It is both where Seeds are searched for and an allow-list: no device outside the Scope is ever logged into.
_Avoid_: Range list, targets, subnet list

**Seed**:
A device inside the Scope that is logged into without first being learned from a Neighbour.
_Avoid_: First target, starting device, root

**Neighbour**:
A device advertised to a visited device through CDP or LLDP.
_Avoid_: Peer, adjacent device

**Visited Device**:
A device the tool has logged into during a Run.
_Avoid_: Managed device, polled device

**Unvisited Device**:
A device known to exist (from a Neighbour advertisement, MAC table or ARP table) that was not logged into, or not fully examined, because it is outside the Scope, unsupported, unreachable, or refused by the connection safety policy.
_Avoid_: Unmanaged device, ghost

**Platform**:
The operating system family of a device, which decides the commands it is sent: IOS/IOS-XE (Catalyst), NX-OS (Nexus), or PAN-OS (Palo Alto). v1 supports only IOS/IOS-XE and NX-OS; a device on any other Platform is an Unvisited Device.
_Avoid_: Vendor, model, device type

**Run**:
One execution of the tool against one Scope, from first sweep to final outputs.
_Avoid_: Job, scan, session

## Access

**Credential Set**:
One username and password the operator supplies for a Run. The password exists only in memory for that Run and is never written anywhere; the username may be.
_Avoid_: Login, account, profile

**Retired Credential Set**:
A Credential Set that is no longer tried for the rest of a Run because it used up its allowance of failed logins.
_Avoid_: Locked set, disabled set

**Trust Store**:
The operator's record, kept between Runs, of trusted SSH host keys and pinned HTTPS certificate fingerprints, against which every device is checked before a password is sent.
_Avoid_: Known hosts, key cache, trust list

## Outputs

**Backup**:
The running configuration of a Visited Device captured during a Run, held encrypted at rest.
_Avoid_: Config dump, snapshot, archive

**Topology**:
The devices, Links and L3 Adjacencies found during a Run, from which the diagram is drawn.
_Avoid_: Network map, graph

**Link**:
A physical connection between two device interfaces, either advertised by CDP/LLDP or inferred from MAC and ARP tables.
_Avoid_: Connection, edge, cable

**L3 Adjacency**:
A routed relationship between two devices, such as a shared subnet or a routing protocol neighbourship.
_Avoid_: Route, peering

**VLAN Mismatch**:
A VLAN that is allowed or present on one end of a Link but not on the other.
_Avoid_: VLAN error, trunk mismatch
