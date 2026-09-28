import hashlib
import re

OP_RE = re.compile(r"\b(HTTP|CONFIG|NET|FILE|PROC|SSH|L4|L7):([A-Z*][A-Z0-9_*]*)(?:\s+(DENIED|ALLOWED|BLOCKED))?")
KV_RE = re.compile(r"\b([a-z_][a-z0-9_]*)=(\"[^\"]*\"|\S+)")


def parse_line(line):
    line = line.strip()
    if not line:
        return None
    m = OP_RE.search(line)
    if not m:
        return None
    family, verb, outcome = m.group(1), m.group(2), m.group(3)
    event = {
        "line_digest": hashlib.sha256(line.encode("utf-8")).hexdigest(),
        "fields": {k: v.strip('"') for k, v in KV_RE.findall(line)},
    }
    if outcome:
        event["openshell_op"] = family + ":" + outcome
        event["method"] = verb
    else:
        event["openshell_op"] = family + ":" + verb
    event["class_name"] = event["openshell_op"]
    return event


def parse_log(text):
    events, skipped = [], 0
    for line in text.splitlines():
        event = parse_line(line)
        if event is None:
            if line.strip():
                skipped += 1
            continue
        events.append(event)
    return events, skipped
