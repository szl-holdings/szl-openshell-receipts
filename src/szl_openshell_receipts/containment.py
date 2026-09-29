# SZL filesystem containment witness.
# Original SZL implementation. openshell-prover was studied only as a black box
# through its CLI output; no OpenShell source is copied, vendored, or linked.


def norm(p):
    p = str(p).strip()
    while len(p) > 1 and p.endswith("/"):
        p = p[:-1]
    return p


def covers(boundary_path, path):
    b, p = norm(boundary_path), norm(path)
    return b == "/" or p == b or p.startswith(b + "/")


def _fs(policy):
    fs = (policy or {}).get("filesystem_policy") or {}
    return [norm(x) for x in fs.get("read_only") or []], [norm(x) for x in fs.get("read_write") or []]


def grants(policy):
    ro, rw = _fs(policy)
    return {"read": ro + rw, "write": list(rw)}


def violations(candidate, boundary):
    g = grants(boundary)
    ro, rw = _fs(candidate)
    out = []
    for access, paths in (("read", ro), ("write", rw)):
        for p in paths:
            if not any(covers(b, p) for b in g[access]):
                out.append({"domain": "filesystem", "access": access, "path": p})
    return out


def check(candidate, boundary):
    v = violations(candidate, boundary)
    return {"schema": "szl.containment-witness/v1", "result": "exceeds_boundary" if v else "within_boundary", "violations": v}


def repair(candidate, boundary):
    g = grants(boundary)
    ro, rw = _fs(candidate)
    new_ro = [p for p in ro if any(covers(b, p) for b in g["read"])]
    new_rw = []
    for p in rw:
        if any(covers(b, p) for b in g["write"]):
            new_rw.append(p)
        elif any(covers(b, p) for b in g["read"]):
            new_ro.append(p)
    fs = {}
    if new_ro:
        fs["read_only"] = sorted(set(new_ro))
    if new_rw:
        fs["read_write"] = sorted(set(new_rw))
    return {"version": 1, "filesystem_policy": fs}


def to_yaml(policy):
    lines = ["version: %d" % int(policy.get("version", 1))]
    fs = policy.get("filesystem_policy") or {}
    if not fs:
        lines.append("filesystem_policy: {}")
    else:
        lines.append("filesystem_policy:")
        for key in ("read_only", "read_write"):
            if fs.get(key):
                lines.append("  %s:" % key)
                lines.extend("    - %s" % p for p in fs[key])
    return "\n".join(lines) + "\n"
