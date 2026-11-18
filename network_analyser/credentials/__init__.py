"""The `credentials` module: Credential Sets in memory only, and the `Secret` type.

Owns the order sets are tried in, Platform limits, the failure budget and retirement, and the
secret scan. A Credential Set password is held only here and in `device_gateway`; the Backup
Passphrase is held only in `backup_store` (CODING_STANDARDS.md, "Secrets").
"""

from network_analyser.credentials.secret import Secret
from network_analyser.credentials.sets import MAX_SETS, CredentialSet, CredentialSets

__all__ = ["MAX_SETS", "CredentialSet", "CredentialSets", "Secret"]
