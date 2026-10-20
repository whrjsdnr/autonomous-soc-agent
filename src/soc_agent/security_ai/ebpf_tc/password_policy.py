"""Narrow OS PAM policy qualification, never a PAM implementation or password reader."""


def validate_pam_inputs(inputs: dict[str, str]) -> None:
    expected = {
        "SOC_AUTH_PAM_SHA": [
            "session required pam_limits.so",
            "session required pam_env.so readenv=1 user_readenv=0",
            "session required pam_env.so readenv=1 envfile=/etc/default/locale user_readenv=0",
            "@include common-auth",
            "@include common-account",
            "@include common-session-noninteractive",
        ],
        "SOC_AUTH_COMMON_SHA": [
            "auth [success=1 default=ignore] pam_unix.so nullok",
            "auth requisite pam_deny.so",
            "auth required pam_permit.so",
            "auth optional pam_cap.so",
        ],
        "SOC_AUTH_ACCOUNT_SHA": [
            "account [success=1 new_authtok_reqd=done default=ignore] pam_unix.so",
            "account requisite pam_deny.so",
            "account required pam_permit.so",
        ],
    }
    actual = {
        key: [
            " ".join(line.split())
            for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        for key, text in inputs.items()
    }
    if actual != expected:
        raise ValueError("OS_AUTH_PAM_POLICY_UNSUPPORTED")
    # nullok is accepted only alongside the root entry's mandatory nonempty local
    # shadow password hash check. Never infer a challenge from PAM exit status alone.
