LINK_LOCAL_PREFIXES = ("169.254.", "fe80:")
METADATA_HOSTS = {"169.254.169.254", "metadata.google.internal", "metadata"}
OPAQUE_BINARIES = {"git-remote-https", "ssh", "nc"}


def reach_set(policy):
    out = set()
    for rule in policy.get("rules", []):
        methods = rule.get("methods") or ["*"]
        for method in methods:
            out.add((str(rule["binary"]), str(rule["host"]).lower(), int(rule["port"]),
                     str(method).upper(), bool(rule.get("credentialed"))))
    return out


def _as_dict(t):
    return {"binary": t[0], "host": t[1], "port": t[2], "method": t[3], "credentialed": t[4]}


def delta(old, new):
    a, b = reach_set(old), reach_set(new)
    wildcards = {(x[0], x[1], x[2], x[4]) for x in a if x[3] == "*"}
    added = sorted(t for t in b - a if (t[0], t[1], t[2], t[4]) not in wildcards)
    removed = sorted(a - b)
    old_cred = {(x[0], x[1], x[2]) for x in a if x[4]}
    findings = []
    seen = set()

    def add(category, t):
        key = (category, t[0], t[1], t[2], t[3])
        if key not in seen:
            seen.add(key)
            findings.append({"category": category, "binary": t[0], "host": t[1], "port": t[2], "method": t[3]})

    for t in added:
        binary, host, port, method, cred = t
        base = binary.replace("\\", "/").rsplit("/", 1)[-1]
        if host.startswith(LINK_LOCAL_PREFIXES) or host in METADATA_HOSTS:
            add("link_local_reach", t)
        if cred:
            if base in OPAQUE_BINARIES:
                add("l7_bypass_credentialed", t)
            if (binary, host, port) not in old_cred:
                add("credential_reach_expansion", t)
            else:
                add("capability_expansion", t)
    return {
        "added": [_as_dict(t) for t in added],
        "removed": [_as_dict(t) for t in removed],
        "findings": findings,
        "expansion_ratio": round(len(added) / max(1, len(a)), 6),
        "witness": "szl-reach-set-v0 (independent simplified model; not equivalent to the OpenShell prover)",
    }


def gate(witness_findings, prover_findings=None, security_notes=()):
    wc = sorted({f["category"] for f in witness_findings})
    reasons = []
    if wc:
        reasons.append("witness findings: " + ",".join(wc))
    if security_notes:
        reasons.append("security notes present")
    if prover_findings is None:
        reasons.append("no prover result supplied; second witness missing")
    else:
        pc = sorted(set(prover_findings))
        if pc:
            reasons.append("prover findings: " + ",".join(pc))
        if pc != wc:
            reasons.append("WITNESS_DISAGREEMENT")
    return {"decision": "ALLOW_ELIGIBLE" if not reasons else "REVIEW_REQUIRED",
            "reasons": reasons, "witness_categories": wc}
