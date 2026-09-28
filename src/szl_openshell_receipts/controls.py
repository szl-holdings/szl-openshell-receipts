from .chain import digest

LABELS = ("MEASURED", "REPORTED", "UNKNOWN", "UNAVAILABLE")
REQUIRED = ("id", "requirement", "control", "owner", "evidence", "status")


def validate_ledger(ledger):
    problems = []
    ids = set()
    controls = ledger.get("controls") or []
    if not controls:
        problems.append("ledger has no controls")
    for i, c in enumerate(controls):
        for k in REQUIRED:
            if not str(c.get(k, "")).strip():
                problems.append("%s: missing %s" % (c.get("id", i), k))
        if c.get("status") not in LABELS:
            problems.append("%s: status must be one of %s" % (c.get("id", i), ",".join(LABELS)))
        if c.get("status") == "MEASURED" and not c.get("evidence_ref"):
            problems.append("%s: MEASURED requires evidence_ref" % c.get("id", i))
        if c.get("id") in ids:
            problems.append("%s: duplicate id" % c.get("id"))
        ids.add(c.get("id"))
    counts = {}
    for c in controls:
        counts[c.get("status")] = counts.get(c.get("status"), 0) + 1
    return (not problems), problems, {"ledger_digest": digest(ledger), "status_counts": counts}
