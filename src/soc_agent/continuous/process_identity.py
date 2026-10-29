"""Observed identity of an ordinary service after exec; never execution authority."""


def validate_ordinary_process(status: str) -> None:
    """Keep the UID/capability boundary strict and preserve a useful failure code."""
    required = ("Uid", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs")
    fields: dict[str, list[str]] = {}
    for line in status.splitlines():
        name, separator, body = line.partition(":")
        if separator and name in required:
            if name in fields:
                raise ValueError("ORDINARY_PROCESS_DUPLICATE_FIELD:" + name)
            fields[name] = body.split()
    if missing := set(required) - fields.keys():
        raise ValueError("ORDINARY_PROCESS_IDENTITY_INCOMPLETE:" + ",".join(sorted(missing)))
    if fields["Uid"] != ["1000"] * 4:
        raise ValueError("ORDINARY_PROCESS_UID_MISMATCH:" + ",".join(fields["Uid"]))
    for name in required[1:-1]:
        if len(fields[name]) != 1:
            raise ValueError("ORDINARY_PROCESS_CAPABILITY_UNVERIFIED:" + name)
        try:
            mask = int(fields[name][0], 16)
        except ValueError as error:
            raise ValueError("ORDINARY_PROCESS_CAPABILITY_UNVERIFIED:" + name) from error
        if mask:
            raise ValueError("ORDINARY_PROCESS_CAPABILITY_NONZERO:" + name)
    if fields["NoNewPrivs"] != ["1"]:
        raise ValueError("ORDINARY_PROCESS_NO_NEW_PRIVILEGES_UNVERIFIED")
