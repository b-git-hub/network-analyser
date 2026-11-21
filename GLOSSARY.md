# Network Analyser

An operator-run tool that discovers the network devices inside a set of IP ranges, backs up their running configuration, and draws how they connect.

## Discovery

**Scope**:
The set of IP ranges the operator gives for a Run. It is an allow-list: no device outside the Scope is ever logged into. It is also where an optional Sweep looks for Seeds.
_Avoid_: Range list, targets, subnet list

**Seed**:
A device inside the Scope that is logged into without first being learned from a Neighbour. Seeds are given by the operator, or found by a Sweep.
_Avoid_: First target, starting device, root

**Sweep**:
An optional probe of every address in the Scope for devices that answer SSH, run to find Seeds the operator did not give.
_Avoid_: Scan, discovery, ping sweep

**Neighbour**:
A device advertised to a visited device through CDP or LLDP.
_Avoid_: Peer, adjacent device

**Visited Device**:
A device the tool logged into during a Run and identified as a supported Platform. Its examination may still be partial.
_Avoid_: Managed device, polled device

**Unvisited Device**:
A device known to exist (from a Neighbour advertisement, routing data, MAC table or ARP table) that is not a Visited Device. Either it was not logged into, because it is outside the Scope, advertised as an unsupported Platform, known only from routing or ARP data, unreachable, or refused by the connection safety policy; or it was logged into but found to be an unsupported Platform, and left at once.
_Avoid_: Unmanaged device, ghost

**Platform**:
The operating system family of a device, which decides the commands it is sent: IOS/IOS-XE (Catalyst), NX-OS (Nexus), or PAN-OS (Palo Alto). v1 supports only IOS/IOS-XE and NX-OS; a device on any other Platform is an Unvisited Device.
_Avoid_: Vendor, model, device type

**Run**:
One execution of the tool against one Scope, from its first login to its final outputs.
_Avoid_: Job, scan, session

## Access

**Credential Set**:
One username and password the operator supplies for a Run. The password exists only in memory for that Run and is never written anywhere; the username may be.
_Avoid_: Login, account, profile

**Device Role**:
The permissions the operator gives the tool's account on a device: exactly the commands the tool sends, and no more. The Credential Set is what logs in; the Device Role is what that login may do.
_Avoid_: Read-only user, service account role, tool profile

**Retired Credential Set**:
A Credential Set that is no longer tried for the rest of a Run because it used up its allowance of failed logins.
_Avoid_: Locked set, disabled set

**Backup Passphrase**:
The one passphrase the operator types at the start of each Run that locks every Backup and the stored Cisco API Key, and that is needed again to open them. Like a Credential Set password, it exists only in memory for that Run and is never written anywhere.
_Avoid_: Backup password, encryption key, master password

**Cisco API Key**:
The client ID and secret the operator registers with Cisco, needed for any Cisco lookup. It is the only secret the tool keeps between Runs, and it is kept locked with the Backup Passphrase.
_Avoid_: API token, Cisco credentials, licence key

**Trust Store**:
The operator's record, kept between Runs, of trusted SSH host keys (and, once an HTTPS Platform is supported, pinned certificate fingerprints), against which every device is checked before a password is sent.
_Avoid_: Known hosts, key cache, trust list

**Run register**:
The operator's list, kept between Runs, of the Run folders the tool has created, used to find every Backup when the Backup Passphrase changes.
_Avoid_: Run index, history

## Outputs

**Run folder**:
The folder a Run writes everything it produces into: its Backups, Topology, diagram, Run report, Findings report and Audit log. Every Run gets a new one, and the tool never deletes it.
_Avoid_: Output directory, results folder, run directory

**Run report**:
The page a Run writes when it ends, saying what it found and what needs the operator's attention: the devices visited and not visited, the Backups taken and missed, and the problems found. Teammates may read it, so it never holds a password or device output.
_Avoid_: Summary, results, output report

**Findings report**:
The page a Run writes that lists every Finding, each with its device, without the rest of the estate, so it can be handed to whoever fixes them. Like the Run report, teammates may read it, so it never holds a password or device output.
_Avoid_: Vulnerability report, findings export, scan report

**Audit log**:
The record, written as a Run goes, of what the tool did, in order: each connection, host-key check, login attempt and command sent. It is the evidence that the Run stayed read-only and inside the Scope, and it never holds a password or device output.
_Avoid_: Debug log, session log, trace

**Backup**:
The running configuration of a Visited Device captured during a Run, held encrypted at rest.
_Avoid_: Config dump, snapshot, archive

**Topology**:
The devices, Links and L3 Adjacencies found during a Run, from which the diagram is drawn.
_Avoid_: Network map, graph

**Link**:
A physical connection between two device interfaces, either advertised by CDP/LLDP or inferred from MAC and ARP tables. Several Links may form a Bundle.
_Avoid_: Connection, edge, cable

**Bundle**:
Several Links joined into one logical channel (a port-channel), including one whose far ends sit on the two peers of a vPC pair.
_Avoid_: LAG, aggregate link, trunk

**Shared Segment**:
A part of the network the tool cannot see, such as an unmanaged switch or hub, known only because one interface hears two or more Neighbours.
_Avoid_: Cloud, hub, unknown switch

**L3 Adjacency**:
A routed relationship between two devices, such as a shared subnet or a routing protocol neighbourship.
_Avoid_: Route, peering

**Subnet**:
An IP prefix within one VRF that interfaces on three or more devices share, placing all of them in L3 Adjacency with one another.
_Avoid_: Network, LAN, segment

**VLAN Mismatch**:
A disagreement in VLAN settings between the two ends of a Link or Bundle: a VLAN carried on one end but not the other, differing native VLANs, a trunk facing an access port, or differing access VLANs.
_Avoid_: VLAN error, trunk mismatch

## Analysis

**Analysis**:
The part of a Run that tests what was collected from Visited Devices against every Check, and raises Findings.
_Avoid_: Audit, scan, assessment

**Check**:
One rule the tool tests a device, Link or the whole network against, such as "the software is named in a Critical Advisory" or "Telnet is enabled".
_Avoid_: Test, rule, policy

**Finding**:
One problem a Check found, with a level, on a device, a Link or the network. A VLAN Mismatch is one kind of Finding.
_Avoid_: Issue, alert, vulnerability, result

**Level**:
How bad a Finding is: Critical, High, Medium or Low, worst first. There is no Info level, and nothing can be switched off, suppressed or accepted in this release.
_Avoid_: Severity, priority, score

**Advisory**:
A vendor's published security advisory (for Cisco, a PSIRT advisory) that names the software versions it affects.
_Avoid_: CVE, bulletin, vulnerability notice

**Train**:
One release line of a Platform's software, such as IOS-XE 17.12, IOS 15.2E, NX-OS 7.0(3)I7 or NX-OS 6.0(2)U6, whose releases share features and hardware support. Within a Train, a lettered release comes after its plain release and before the next one: 17.12.7, 17.12.7a, 17.12.7b, 17.12.8.
_Avoid_: Branch, stream, major version

**Upgrade Target**:
The release a device should move to at least, to clear every Critical and High Advisory that names its release and has a fix in the device's own Train. For each such Advisory, take the lowest of Cisco's first-fixed releases in that Train that is above the running release; the Upgrade Target is the highest of those. When some of the Advisories have no fix in the Train, the Upgrade Target says how many it does not clear. It is advice attached to the device's Advisory result, not a Finding.
_Avoid_: Fixed version, recommended release

**Latest Release**:
The highest release, by version order, that Cisco lists as compatible with a device's model, both within the device's own Train and overall. Every release Cisco lists counts, whatever its lifecycle; release dates are never used. It is advice shown beside the Upgrade Target, not a Finding.
_Avoid_: Current version, newest version

**Suggested Release**:
A release Cisco itself suggests for a device's model. A device not running one raises a Finding.
_Avoid_: Recommended release, golden image, Upgrade Target
