# SZL filesystem containment witness.
# Original SZL implementation. openshell-prover was studied only as a black box
# through its CLI output; no OpenShell source is copied, vendored, or linked.

import os
import stat
from collections import deque


def norm(p):
    if not isinstance(p, str) or not p.startswith("/") or "\\" in p:
        raise ValueError("absolute POSIX path required")
    if any(ord(char) < 32 for char in p) or ".." in p.split("/"):
        raise ValueError("invalid or traversing path")
    return "/" + "/".join(part for part in p.split("/") if part not in ("", "."))


def covers(boundary_path, path):
    try:
        b, p = norm(boundary_path), norm(path)
        if not (b == "/" or p == b or p.startswith(b + "/")):
            return False
        # This witness observes local resolution; it is not a remote-host sandbox.
        real_b, real_p = _resolved(b), _resolved(p)
        return os.path.commonpath((real_b, real_p)) == real_b
    except (OSError, ValueError, TypeError, RuntimeError):
        return False


def _resolved(path):
    """Resolve symlinks, allowing absent suffixes but never suppressing errors."""
    pending, resolved, links = deque(path.split("/")), [], 0
    while pending:
        part = pending.popleft()
        if part in ("", "."):
            continue
        if part == "..":  # May occur inside a symlink target only.
            if resolved:
                resolved.pop()
            continue
        candidate = "/" + "/".join([*resolved, part])
        try:
            info = os.lstat(candidate)
        except FileNotFoundError:
            resolved.append(part)
            continue
        if stat.S_ISLNK(info.st_mode):
            links += 1
            if links > 40:
                raise ValueError("symlink resolution limit")
            target = os.readlink(candidate)
            if target.startswith("/"):
                resolved = []
            pending.extendleft(reversed(target.split("/")))
        else:
            resolved.append(part)
    return "/" + "/".join(resolved)


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
