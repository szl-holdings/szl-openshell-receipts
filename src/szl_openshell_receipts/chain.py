import datetime
import hashlib
import json

SCHEMA = "szl.openshell.receipt/v0.2"
GENESIS = "0" * 64
DENY_WORDS = ("disallow", "deny", "denied", "block", "reject", "refused")
REVIEW_WORDS = ("propos", "escalat", "review", "pending", "approval")
ALLOW_WORDS = ("allow", "permit", "approved", "accept")
DECISION_KEYS = ("decision", "disposition", "action", "verdict", "status", "outcome",
                 "type", "kind", "class_name", "activity_name")


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(obj):
    return hashlib.sha256(canonical(obj)).hexdigest()


def classify(event):
    op = str(event.get("openshell_op") or "").upper()
    if op:
        if op.endswith("DENIED") or op.endswith("BLOCKED") or op == "CONFIG:REJECTED":
            return "DENY"
        if op == "CONFIG:PROPOSED":
            return "REVIEW_REQUIRED"
        if op == "CONFIG:APPROVED" or op.endswith("ALLOWED"):
            return "ALLOW"
        return "OBSERVED"
    text = " ".join(str(event.get(k)).lower() for k in DECISION_KEYS
                    if isinstance(event.get(k), (str, int, float)))
    if any(w in text for w in DENY_WORDS):
        return "DENY"
    if any(w in text for w in REVIEW_WORDS):
        return "REVIEW_REQUIRED"
    if any(w in text for w in ALLOW_WORDS):
        return "ALLOW"
    return "OBSERVED"


def flags_for(event):
    flags = []
    op = str(event.get("openshell_op") or "").upper()
    fields = event.get("fields") or {}
    if op == "CONFIG:APPROVED" and str(fields.get("auto", "")).lower() == "true":
        if str(fields.get("prover_delta", "")).lower() != "empty":
            flags.append("AUTO_APPROVAL_WITH_NONEMPTY_DELTA")
    return flags


class ReceiptChain:
    def __init__(self, run_id, policy_hash, source_commit):
        self.run_id = run_id
        self.policy_hash = policy_hash
        self.source_commit = source_commit
        self.receipts = []

    def append(self, event, observed_utc=None):
        prev = self.receipts[-1]["receipt_digest"] if self.receipts else GENESIS
        body = {
            "schema": SCHEMA,
            "run_id": self.run_id,
            "seq": len(self.receipts),
            "policy_hash": self.policy_hash,
            "source_commit": self.source_commit,
            "event_digest": digest(event),
            "event_kind": str(event.get("openshell_op") or event.get("class_name") or event.get("kind") or "unknown"),
            "decision": classify(event),
            "evidence_basis": "OPENSHELL_LOG_TOKEN" if event.get("openshell_op") else "KEYWORD_HEURISTIC",
            "flags": flags_for(event),
            "observed_utc": observed_utc or datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "prev_digest": prev,
            "signature_status": "UNSIGNED_HONEST",
        }
        body["receipt_digest"] = digest(body)
        self.receipts.append(body)
        return body


def verify_chain(receipts):
    prev = GENESIS
    for index, receipt in enumerate(receipts):
        body = {k: v for k, v in receipt.items() if k != "receipt_digest"}
        if receipt.get("seq") != index:
            return False, "sequence break at %d" % index
        if receipt.get("prev_digest") != prev:
            return False, "prev_digest mismatch at %d" % index
        if digest(body) != receipt.get("receipt_digest"):
            return False, "digest mismatch at %d" % index
        prev = receipt["receipt_digest"]
    return True, "verified %d receipts" % len(receipts)
