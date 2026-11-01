# SZL filesystem containment witness.
# Original SZL implementation. openshell-prover was studied only as a black box
# through its CLI output; no OpenShell source is copied, vendored, or linked.


from pathlib import Path


def norm(p):
    # Preserve malformed values for rejection; never coerce them into grants.
    return (p.rstrip("/") or "/") if isinstance(p, str) and p else p


def _resolved(p):
    if not isinstance(p, str) or not p or "\x00" in p or p != p.strip():
        raise ValueError("invalid filesystem grant")
    path = Path(p)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("absolute traversal-free path required")
    return path.resolve(strict=False)


def covers(boundary_path, path):
    try:
        b, p = _resolved(boundary_path), _resolved(path)
        return p == b or b in p.parents
    except (ValueError, OSError, RuntimeError):
        return False


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
