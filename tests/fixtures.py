"""Shared pieces for synthetic fixtures.

Credential-directory paths, private addresses and secret-shaped strings are assembled at runtime, so a
secret scanner run over this repository does not flag the test sources themselves. All values are fake.
"""
SSH = "~" + "/.ssh"
AWS = "~" + "/.aws"
GCLOUD = "~" + "/.config/gcloud"
REL_SSH = "." + "ssh"            # relative to the current directory
REL_AWS = "." + "aws"
ROOT_SSH = "/ro" + "ot/.ssh"      # root's home directory
PEM_BEGIN = "-----BEGIN %sPRIV" + "ATE KEY-----"
PEM_END = "-----END %sPRIV" + "ATE KEY-----"


def ip(*parts):
    """ip(a, b, c, d) -> the dotted-quad string."""
    return ".".join(str(p) for p in parts)
