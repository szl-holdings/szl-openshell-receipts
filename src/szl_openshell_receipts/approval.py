import hashlib


def _h(value):
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def approval_event(chunk_id, candidate_hash, review_token, approver, decision, expires_utc, reason=""):
    if decision not in ("approve", "reject"):
        raise ValueError("decision must be approve or reject")
    if not review_token:
        raise ValueError("review_token is required; approvals must bind to the live candidate")
    return {
        "class_name": "szl_approval",
        "openshell_op": "CONFIG:APPROVED" if decision == "approve" else "CONFIG:REJECTED",
        "chunk_id": str(chunk_id),
        "candidate_hash": str(candidate_hash),
        "review_token_digest": _h(review_token),
        "approver": str(approver),
        "expires_utc": str(expires_utc),
        "reason_digest": _h(reason),
        "fields": {"auto": "false"},
    }
