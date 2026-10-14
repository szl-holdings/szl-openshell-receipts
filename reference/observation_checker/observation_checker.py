"""SZL standalone, zero-model, offline observation-consistency reference.

Pure check_json/check_bundle functions: no reads, writes, network, models or effect
outputs. CLI reads one bounded JSON bundle and optional independent policy file,
then prints diagnostics. Supplied evidence is not authenticated by this checker.
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from typing import Any

VERSION = "szl-observation-checker/1"
MAX_BYTES = 131072
MAX_RECORDS = 64
MAX_ATTEMPTS = 8
MAX_DEPTH = 12
CLASSES = {"SYNTHETIC", "HISTORICAL_EXECUTION", "CURRENT_SOURCE_ONLY", "OBSERVED_EXECUTION"}
METHODS = {"FIXTURE", "LOCAL_SPY", "HTTP", "LOCAL_MEMORY", "DURABLE_STORE_READBACK", "FRESH_PROCESS_READBACK", "SOURCE_REVIEW", "VERIFIER", "INDEPENDENT_ASSESSMENT"}
BIND_KEYS = {"tenant", "session", "action", "run", "plan", "step", "stage", "generation", "policy_epoch", "source_revision", "source_tree"}
FINDINGS = ("schema", "identity", "lifecycle", "accounting", "budget", "admission", "durability", "restoration", "support_assessment", "claim_strength", "current_runtime_evidence")
DATA_KEYS = {
    "submission": {"status"}, "admission": {"decision"},
    "source_grant": {"grant_id", "decision"}, "hydration": {"source_digest"},
    "generation": {"generation"}, "dispatch": set(), "not_invoked": set(),
    "outcome": {"outcome", "result_digest", "process_id"}, "timeout": set(),
    "cancel_request": set(), "cancel_ack": set(), "effects_stopped": set(),
    "durable_ack": {"result_digest", "storage_ref"},
    "restore": {"result_digest", "ack_id", "process_id"},
    "closure": {"status"}, "cleanup": {"status"},
    "support_assessment": {"result_digest", "verdict"},
    "attempt": {"state", "cost"}, "transport": {"status", "handles_only"},
    "local_contract": {"deployed"},
    "historical_test": {"tested_tree", "python", "passed"},
    "plan": {"mode", "status"}, "legacy_snapshot": {"phase", "value_digest"},
    "runtime_observation": {"tree", "python"}, "signature_integrity": {"valid"},
}
STATES = {"RESERVED_UNSENT", "ACTIVE", "UNKNOWN", "SETTLED", "ABANDONED_UNSENT"}
TRANSITIONS = {
    "RESERVED_UNSENT": {"RESERVED_UNSENT", "ACTIVE", "ABANDONED_UNSENT"},
    "ACTIVE": {"ACTIVE", "UNKNOWN", "SETTLED"},
    "UNKNOWN": {"UNKNOWN", "SETTLED"}, "SETTLED": {"SETTLED"},
    "ABANDONED_UNSENT": {"ABANDONED_UNSENT"},
}
LIMITATIONS = [
    "All evidence and policy are supplied observations; authenticity, independence and real-world completeness are not established.",
    "PASS is limited to the named consistency predicate over this bundle; it grants no authority, correctness, deployment or exactly-once qualification.",
    "No trust root, cryptographic signature verification, live adapter, scheduler, recovery action, model or external integration is implemented.",
    "Attempt counts do not establish wall-clock termination or absence of unobserved effects; timeout and cancellation acknowledgement do not establish stopped effects.",
]


class SchemaError(ValueError):
    """Closed, bounded input contract rejected."""


def _need(ok: bool, code: str) -> None:
    if not ok:
        raise SchemaError(code)


def _keys(value: Any, keys: set[str], label: str) -> None:
    _need(type(value) is dict and set(value) == keys, label + ":keys")


def _text(value: Any, label: str, maximum: int = 128) -> None:
    _need(type(value) is str and 0 < len(value) <= maximum and all(32 <= ord(c) < 127 for c in value), label + ":string")


def _digest(value: Any, label: str) -> None:
    _need(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None, label + ":digest")


def _rev(value: Any, label: str) -> None:
    _need(type(value) is str and re.fullmatch(r"[0-9a-f]{40}", value) is not None, label + ":revision")


def _integer(value: Any, label: str, maximum: int = 1000000) -> None:
    _need(type(value) is int and 0 <= value <= maximum, label + ":integer")


def _enum(value: Any, options: set[str], label: str) -> None:
    _need(type(value) is str and value in options, label + ":enum")


def _time(value: Any) -> datetime:
    _need(type(value) is str and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value) is not None, "timestamp:format")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise SchemaError("timestamp:calendar") from exc


def _depth(value: Any, depth: int = 0) -> None:
    _need(depth <= MAX_DEPTH, "input:depth")
    if type(value) is dict:
        _need(len(value) <= 32 and all(type(k) is str for k in value), "object:size_or_key")
        for v in value.values():
            _depth(v, depth + 1)
    elif type(value) is list:
        _need(len(value) <= MAX_RECORDS, "array:size")
        for v in value:
            _depth(v, depth + 1)
    elif type(value) is str:
        _need(len(value) <= 512, "string:size")
    elif value is not None and type(value) not in (bool, int):
        raise SchemaError("value:type_no_floats")


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n"


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        _need(key not in result, "json:duplicate_key")
        result[key] = value
    return result


def parse_json(raw: str | bytes) -> Any:
    if type(raw) is bytes:
        _need(len(raw) <= MAX_BYTES, "input:bytes")
        try:
            raw = raw.decode("utf-8")
        except UnicodeError as exc:
            raise SchemaError("json:utf8") from exc
    _need(type(raw) is str, "input:type")
    try:
        _need(len(raw.encode("utf-8")) <= MAX_BYTES, "input:bytes")
        value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=lambda _: (_ for _ in ()).throw(SchemaError("json:nonfinite")))
        _depth(value)
        return value
    except SchemaError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise SchemaError("json:malformed") from exc


def _validate(bundle: Any, policy: Any) -> None:
    _depth(bundle)
    _need(len(canonical(bundle).encode("ascii")) <= MAX_BYTES, "input:bytes")
    _keys(bundle, {"schema", "ordering", "evidence_class", "interval", "max_age_seconds", "source", "journey", "records", "result", "accounting", "claims"}, "bundle")
    _need(type(bundle["schema"]) is int and bundle["schema"] == 1, "schema:version")
    _need(bundle["ordering"] == "EXPLICIT_SEQUENCE", "ordering:unsupported")
    _enum(bundle["evidence_class"], CLASSES, "evidence_class")
    _keys(bundle["interval"], {"start", "end"}, "interval")
    start, end = (_time(bundle["interval"][key]) for key in ("start", "end"))
    _need(start <= end, "interval:order")
    _integer(bundle["max_age_seconds"], "max_age_seconds", 86400)
    _keys(bundle["source"], {"repository", "revision", "tree", "exporter_schema", "python"}, "source")
    for key in ("repository", "exporter_schema", "python"):
        _text(bundle["source"][key], "source:" + key)
    for key in ("revision", "tree"):
        _rev(bundle["source"][key], "source:" + key)
    _keys(bundle["journey"], BIND_KEYS - {"source_revision", "source_tree"}, "journey")
    for key, value in bundle["journey"].items():
        (_digest if key == "plan" else _text)(value, "journey:" + key)
    _need(type(bundle["records"]) is list and len(bundle["records"]) <= MAX_RECORDS, "records:size")
    for r in bundle["records"]:
        _keys(r, {"id", "kind", "component", "artifact_digest", "at", "seq", "evidence_class", "method", "binding", "attempt_id", "data"}, "record")
        for key in ("id", "component"):
            _text(r[key], "record:" + key)
        _digest(r["artifact_digest"], "record:artifact")
        _need(start <= _time(r["at"]) <= end, "record:outside_interval")
        _integer(r["seq"], "record:seq")
        _enum(r["evidence_class"], CLASSES, "record:evidence_class")
        _enum(r["method"], METHODS, "record:method")
        _enum(r["kind"], set(DATA_KEYS), "record:kind")
        if r["binding"] is not None:
            _keys(r["binding"], BIND_KEYS, "binding")
            for key, value in r["binding"].items():
                (_rev if key.startswith("source_") else _digest if key == "plan" else _text)(value, "binding:" + key)
        if r["attempt_id"] is not None:
            _text(r["attempt_id"], "attempt_id")
        if r["kind"] in {"attempt", "dispatch", "not_invoked", "outcome", "timeout", "cancel_request", "cancel_ack", "effects_stopped", "durable_ack", "restore", "support_assessment"}:
            _need(r["attempt_id"] is not None, "record:attempt_required")
        d = r["data"]
        _keys(d, DATA_KEYS[r["kind"]], "data:" + r["kind"])
        for key, value in d.items():
            if key in {"result_digest"} and value is None and r["kind"] == "outcome":
                continue
            if key.endswith("digest"):
                _digest(value, "data:" + key)
            elif key in {"deployed", "passed", "handles_only", "valid"}:
                _need(type(value) is bool, "data:boolean")
            elif key in {"cost", "status"} and (key == "cost" or r["kind"] == "transport"):
                _integer(value, "data:" + key)
            else:
                _text(value, "data:" + key)
        kind = r["kind"]
        if kind in {"admission", "source_grant"}:
            _enum(d["decision"], {"ADMITTED", "DENIED"}, "decision")
        if kind == "attempt":
            _enum(d["state"], STATES, "attempt:state")
        if kind == "outcome":
            _enum(d["outcome"], {"ANSWER", "ABSTAINED", "FAILURE", "CANCELLED", "UNKNOWN"}, "outcome")
            _need(d["outcome"] != "ANSWER" or d["result_digest"] is not None, "outcome:result_required")
        if kind == "support_assessment":
            _enum(d["verdict"], {"SUPPORTED", "ABSTAINED", "CONTRADICTED", "UNRESOLVED"}, "assessment")
        if kind == "legacy_snapshot":
            _enum(d["phase"], {"FIRST_CYCLE", "FINAL"}, "snapshot:phase")
        if kind in {"historical_test", "runtime_observation"}:
            _rev(d["tested_tree" if kind == "historical_test" else "tree"], "data:tree")
        if kind == "cleanup":
            _enum(d["status"], {"SUCCEEDED", "FAILED", "UNKNOWN"}, "cleanup")
        if kind == "plan":
            _enum(d["mode"], {"PLAN_ONLY"}, "plan:mode")
            _enum(d["status"], {"READY_TO_ORCHESTRATE", "INCOMPLETE"}, "plan:status")
    _need(len({r["attempt_id"] for r in bundle["records"] if r["attempt_id"] is not None}) <= MAX_ATTEMPTS, "attempts:size")
    if bundle["result"] is not None:
        _keys(bundle["result"], {"digest", "terminal_id", "receipt_refs"}, "result")
        _digest(bundle["result"]["digest"], "result")
        _text(bundle["result"]["terminal_id"], "result:terminal_id")
        refs = bundle["result"]["receipt_refs"]
        _need(type(refs) is list and len(refs) <= 8 and len(refs) == len(set(refs)), "result:refs")
        for ref in refs:
            _text(ref, "result:ref")
    if bundle["accounting"] is not None:
        a = bundle["accounting"]
        _keys(a, {"contract_id", "action", "unit", "limit", "history_complete", "summary_charged"}, "accounting")
        _text(a["contract_id"], "accounting:contract_id")
        _text(a["action"], "accounting:action")
        _need(a["unit"] == "calls", "accounting:unit")
        _integer(a["limit"], "accounting:limit")
        _need(type(a["history_complete"]) is bool, "accounting:history_complete")
        if a["summary_charged"] is not None:
            _integer(a["summary_charged"], "accounting:summary")
    c = bundle["claims"]
    _keys(c, {"ui_status", "durable", "restored", "current_admission", "current_runtime", "deployed", "budget_compliant", "projection_record"}, "claims")
    _enum(c["ui_status"], {"unknown", "success", "finished", "abstained", "cancelled", "ready_to_orchestrate"}, "claims:ui_status")
    for key in ("durable", "restored", "current_admission", "current_runtime", "deployed"):
        _need(type(c[key]) is bool, "claims:boolean")
    _need(c["budget_compliant"] is None or type(c["budget_compliant"]) is bool, "claims:budget")
    if c["projection_record"] is not None:
        _text(c["projection_record"], "claims:projection")
    if policy is not None:
        _depth(policy)
        _keys(policy, {"schema", "generation", "policy_epoch", "source_revision", "source_tree", "at", "expires", "revoked_grants"}, "policy")
        _need(type(policy["schema"]) is int and policy["schema"] == 1, "policy:version")
        for key in ("generation", "policy_epoch"):
            _text(policy[key], "policy:" + key)
        for key in ("source_revision", "source_tree"):
            _rev(policy[key], "policy:" + key)
        _need(_time(policy["at"]) <= _time(policy["expires"]), "policy:order")
        _need(type(policy["revoked_grants"]) is list and len(policy["revoked_grants"]) <= 64, "policy:revocations")
        for grant in policy["revoked_grants"]:
            _text(grant, "policy:grant")


def _finding(status: str, reasons: list[str], ids: list[str] | None = None) -> dict[str, Any]:
    return {"status": status, "reasons": sorted(set(reasons)), "evidence_ids": sorted(set(ids or []))}


def _rejected(code: str) -> dict[str, Any]:
    f = {key: _finding("NOT_APPLICABLE", ["schema_rejected_not_evaluated"]) for key in FINDINGS}
    f["schema"] = _finding("FAIL", [code])
    return {"checker_version": VERSION, "findings": f, "observations": None, "unresolved_references": [], "limitations": LIMITATIONS[:]}


def check_json(raw: str | bytes, policy_raw: str | bytes | None = None) -> dict[str, Any]:
    """Reject malformed JSON without evaluating lifecycle or semantic claims."""
    try:
        return check_bundle(parse_json(raw), parse_json(policy_raw) if policy_raw is not None else None)
    except SchemaError as exc:
        return _rejected(str(exc))


def check_bundle(bundle: Any, policy: Any = None, *, advisory: Any = None) -> dict[str, Any]:
    """Return deterministic diagnostics; advisory is deliberately never inspected.

    Policy is a separate caller-supplied input, not a bundle verification flag.
    Its real independence/currentness cannot be authenticated offline.
    """
    try:
        _validate(bundle, policy)
    except (SchemaError, TypeError, ValueError, RecursionError) as exc:
        return _rejected(str(exc) if isinstance(exc, SchemaError) else "input:malformed")
    f = {key: _finding("UNKNOWN", ["required_evidence_absent"]) for key in FINDINGS}
    f["schema"] = _finding("PASS", ["closed_bounded_schema_valid"])
    expected = dict(bundle["journey"], source_revision=bundle["source"]["revision"], source_tree=bundle["source"]["tree"])
    end = _time(bundle["interval"]["end"])
    by_id: dict[str, dict] = {}
    variants: dict[str, set[str]] = {}
    all_variants: dict[str, dict] = {}
    duplicate_count = 0
    for r in bundle["records"]:
        wire = canonical(r)
        variants.setdefault(r["id"], set())
        if wire in variants[r["id"]]:
            duplicate_count += 1
        variants[r["id"]].add(wire)
        all_variants[wire] = r
        by_id[r["id"]] = r
    conflicts = {rid for rid, wires in variants.items() if len(wires) > 1}
    by_id = {rid: r for rid, r in by_id.items() if rid not in conflicts}
    records = sorted(by_id.values(), key=lambda r: (r["seq"], r["id"]))
    missing = [r["id"] for r in records if r["binding"] is None]
    mismatches = [r["id"] for r in records if r["binding"] is not None and r["binding"] != expected]
    stale = [r["id"] for r in records if (end - _time(r["at"])).total_seconds() > bundle["max_age_seconds"]]
    collisions = [r["id"] for r in records if sum(x["seq"] == r["seq"] for x in records) > 1]
    bad_ids = set(missing + mismatches + stale + collisions) | conflicts
    eligible = [r for r in records if r["id"] not in bad_ids]
    identity_reasons = (["conflicting_record_id"] if conflicts else []) + (["journey_binding_mismatch"] if mismatches else []) + (["sequence_identity_collision"] if collisions else [])
    f["identity"] = _finding("FAIL" if identity_reasons else "UNKNOWN" if missing or stale or not records else "PASS", identity_reasons or (["missing_binding"] if missing else []) + (["stale_evidence"] if stale else []) or ["all_supplied_identities_match"], list(conflicts) + mismatches + collisions + missing + stale or [r["id"] for r in records])
    def rows(kind: str, fresh: bool = True) -> list[dict]:
        return [r for r in (eligible if fresh else records) if r["kind"] == kind]
    def ids(items: list[dict]) -> list[str]:
        return [r["id"] for r in items]
    unresolved: list[str] = []
    result = bundle["result"]
    terminal_ref = by_id.get(result["terminal_id"]) if result else None
    terminal = terminal_ref if terminal_ref and terminal_ref["kind"] == "outcome" else None
    result_fail: list[str] = []
    if result:
        if terminal_ref is None:
            unresolved.append(result["terminal_id"])
        elif terminal is None or terminal["data"]["result_digest"] != result["digest"]:
            result_fail.append("terminal_result_binding_mismatch")
        for ref in result["receipt_refs"]:
            if ref not in by_id or ref in conflicts:
                unresolved.append(ref)
    outcome_groups: dict[str, set[tuple]] = {}
    for r in [v for v in all_variants.values() if v["kind"] == "outcome"]:
        if r["data"]["outcome"] != "UNKNOWN":
            outcome_groups.setdefault(r["attempt_id"], set()).add((r["data"]["outcome"], r["data"]["result_digest"]))
    terminal_conflict = any(len(v) > 1 for v in outcome_groups.values()) or any(v["kind"] == "outcome" and v["id"] in conflicts for v in all_variants.values())
    denial = [v for v in all_variants.values() if v["kind"] in {"admission", "source_grant"}]
    denial = [r for r in denial if r["data"]["decision"] == "DENIED" and r["binding"] == expected]
    dispatch = sorted((v for v in all_variants.values() if v["kind"] == "dispatch"), key=lambda r: (r["seq"], r["id"], canonical(r)))
    denial_dispatch = bool(denial and any(r["binding"] == expected for r in dispatch))
    no_dispatch_conflict = any(a["attempt_id"] == b["attempt_id"] for a in rows("not_invoked", False) for b in dispatch)
    stop_conflict = any(d["attempt_id"] == s["attempt_id"] and d["seq"] > s["seq"] for d in dispatch for s in rows("effects_stopped", False))
    outcome = "UNKNOWN"
    good_terminal = terminal is not None and terminal in eligible and not result_fail and not terminal_conflict and terminal["kind"] == "outcome"
    if good_terminal:
        outcome = terminal["data"]["outcome"]
    elif not result and len(rows("outcome")) == 1 and not terminal_conflict:
        outcome = rows("outcome")[0]["data"]["outcome"]
    lifecycle_errors = result_fail + (["conflicting_terminal_results"] if terminal_conflict else []) + (["denied_stage_dispatched"] if denial_dispatch else []) + (["not_invoked_and_dispatched"] if no_dispatch_conflict else []) + (["dispatch_after_effects_stopped"] if stop_conflict else [])
    terminal_evidence = rows("outcome")
    f["lifecycle"] = _finding("FAIL" if lifecycle_errors else "PASS" if outcome != "UNKNOWN" else "UNKNOWN", lifecycle_errors or (["terminal_outcome_observed"] if outcome != "UNKNOWN" else ["outcome_unresolved_closure_is_not_success"]), ids(terminal_evidence + denial + dispatch + rows("closure")))
    cancel_state = "NOT_OBSERVED"
    if rows("cancel_request"):
        cancel_state = "REQUESTED_EFFECTS_UNKNOWN"
    requested_attempts = {r["attempt_id"] for r in rows("cancel_request")}
    acknowledged_attempts = {r["attempt_id"] for r in rows("cancel_ack") if any(q["attempt_id"] == r["attempt_id"] and q["seq"] < r["seq"] for q in rows("cancel_request"))}
    if requested_attempts and requested_attempts <= acknowledged_attempts:
        cancel_state = "ACKNOWLEDGED_EFFECTS_UNKNOWN"
    stopped_attempts = {r["attempt_id"] for r in rows("effects_stopped") if any(q["attempt_id"] == r["attempt_id"] and q["seq"] < r["seq"] for q in rows("cancel_request"))}
    if requested_attempts and requested_attempts <= stopped_attempts and not stop_conflict:
        cancel_state = "STOPPED_FOR_RECORDED_ATTEMPTS_ONLY"
    if stop_conflict:
        cancel_state = "CONFLICT"
    # Reconstruct attempts by explicit sequence. Unknown and settled remain charged.
    attempt_records = rows("attempt", False)
    attempts: dict[str, dict] = {}
    accounting_errors: list[str] = ["conflicting_evidence_prevents_accounting"] if conflicts else []
    prefix_peak = 0
    prefix_costs = []
    for r in attempt_records:
        aid, d = r["attempt_id"], r["data"]
        prev = attempts.get(aid)
        next_state = d["state"]
        if prev and d["state"] not in TRANSITIONS[prev["state"]]:
            accounting_errors.append("invalid_attempt_state_transition")
            next_state = prev["state"]
        if prev and prev["cost"] != d["cost"]:
            accounting_errors.append("attempt_cost_changed")
        attempts[aid] = {"id": aid, "state": next_state, "cost": max(prev["cost"] if prev else 0, d["cost"]), "evidence_ids": sorted((prev["evidence_ids"] if prev else []) + [r["id"]])}
        prefix_cost = sum(x["cost"] for x in attempts.values() if x["state"] != "ABANDONED_UNSENT")
        prefix_peak = max(prefix_peak, prefix_cost)
        prefix_costs.append({"record_id": r["id"], "cost": prefix_cost})
    if len({d["attempt_id"] for d in dispatch}) != len(dispatch):
        accounting_errors.append("multiple_dispatch_records_for_one_attempt")
    for d in dispatch:
        prior = [r for r in attempt_records if r["attempt_id"] == d["attempt_id"] and r["seq"] < d["seq"] and r["binding"] == expected and r["id"] not in bad_ids]
        if not prior:
            accounting_errors.append("dispatch_without_prior_charge")
        elif prior[-1]["data"]["state"] not in {"RESERVED_UNSENT", "ACTIVE"} or prior[-1]["data"]["cost"] < 1:
            accounting_errors.append("dispatch_without_active_positive_charge")
    for aid, a in attempts.items():
        if a["state"] == "ABANDONED_UNSENT" and any(d["attempt_id"] == aid for d in dispatch):
            accounting_errors.append("dispatched_attempt_refunded")
        if a["state"] in {"ACTIVE", "UNKNOWN", "SETTLED"} and a["cost"] < 1:
            accounting_errors.append("active_attempt_zero_charge")
    # Invalid state/cost transitions retain the maximum previously observed cost.
    charged = sum(a["cost"] for a in attempts.values() if a["state"] != "ABANDONED_UNSENT" or any(d["attempt_id"] == a["id"] for d in dispatch) or "invalid_attempt_state_transition" in accounting_errors)
    a = bundle["accounting"]
    if a and a["action"] != expected["action"]:
        accounting_errors.append("budget_action_mismatch")
    if a and a["summary_charged"] is not None and a["summary_charged"] != charged:
        accounting_errors.append("charged_summary_mismatch")
    physical_kinds = {"dispatch", "not_invoked", "outcome", "timeout", "cancel_request", "cancel_ack", "effects_stopped", "durable_ack", "restore", "support_assessment"}
    missing_attempts = sorted({r["attempt_id"] for r in records if r["kind"] in physical_kinds} - set(attempts))
    incomplete_accounting = a is None or not a["history_complete"] or any(r["id"] in bad_ids for r in attempt_records) or bool(conflicts) or bool(missing_attempts)
    f["accounting"] = _finding("FAIL" if accounting_errors else "UNKNOWN" if incomplete_accounting else "PASS", accounting_errors or (["missing_or_incomplete_bound_attempt_history"] if incomplete_accounting else ["unique_attempt_costs_preserved"]), ids(attempt_records + dispatch))
    budget_errors = (["observed_budget_exceeded"] if a and charged > a["limit"] else []) + (["observed_prefix_budget_exceeded"] if a and prefix_peak > a["limit"] else [])
    f["budget"] = _finding("FAIL" if budget_errors or accounting_errors else "UNKNOWN" if incomplete_accounting else "PASS", budget_errors + accounting_errors or (["actual_budget_unknown"] if incomplete_accounting else ["within_declared_complete_trace_budget"]), ids(attempt_records))
    # Separate policy input can invalidate old grants; a bundle cannot restore policy.
    admission_errors: list[str] = ["explicit_admission_denial"] if denial else []
    if any(v["kind"] in {"admission", "source_grant", "hydration", "generation"} and v["id"] in conflicts for v in all_variants.values()):
        admission_errors.append("conflicting_admission_evidence")
    if any(r["data"]["generation"] != expected["generation"] for r in rows("generation", False)):
        admission_errors.append("generation_observation_mismatch")
    grants = rows("source_grant")
    admitted = [r for r in rows("admission") if r["data"]["decision"] == "ADMITTED"]
    grant_ok = [r for r in grants if r["data"]["decision"] == "ADMITTED"]
    policy_current = False
    if policy is not None:
        matching = all(policy[key] == expected[key] for key in ("generation", "policy_epoch", "source_revision", "source_tree"))
        policy_current = matching and _time(policy["at"]) <= end <= _time(policy["expires"]) and (end - _time(policy["at"])).total_seconds() <= bundle["max_age_seconds"]
        if not matching:
            admission_errors.append("policy_binding_mismatch")
        if any(r["data"]["grant_id"] in policy["revoked_grants"] for r in rows("source_grant", False)):
            admission_errors.append("source_grant_revoked")
    admission_complete = bool(admitted and grant_ok and rows("hydration") and policy_current)
    f["admission"] = _finding("FAIL" if admission_errors else "PASS" if admission_complete else "UNKNOWN", admission_errors or (["bound_current_admission_records_present"] if admission_complete else ["missing_stale_or_unhydrated_admission_evidence"]), ids(rows("admission", False) + rows("source_grant", False) + rows("hydration", False)))
    # Acknowledgements must cite the exact result AND terminal attempt.
    ack_errors: list[str] = ["conflicting_ack_record"] if any(v["kind"] == "durable_ack" and v["id"] in conflicts for v in all_variants.values()) else []
    acks: list[dict] = []
    for ref in result["receipt_refs"] if result else []:
        ack = by_id.get(ref)
        if ack is None or ref in conflicts:
            continue
        if ack["kind"] != "durable_ack":
            ack_errors.append("receipt_ref_wrong_kind")
        elif ack["binding"] is not None and ack["binding"] != expected:
            ack_errors.append("ack_identity_binding_mismatch")
        elif ack["data"]["result_digest"] != result["digest"] or (terminal and ack["attempt_id"] != terminal["attempt_id"]):
            ack_errors.append("ack_result_or_attempt_mismatch")
        elif ack in eligible and ack["method"] == "DURABLE_STORE_READBACK" and good_terminal and ack["seq"] > terminal["seq"]:
            acks.append(ack)
        elif terminal and ack["seq"] <= terminal["seq"]:
            ack_errors.append("ack_precedes_result")
    durability_complete = bool(acks) and result is not None and len(acks) == len(result["receipt_refs"]) and not unresolved
    f["durability"] = _finding("FAIL" if ack_errors else "PASS" if durability_complete else "UNKNOWN", ack_errors or (["bound_durable_ack_present"] if durability_complete else ["durable_ack_missing_unresolved_stale_or_unsuitable"]), ids(acks) + (result["receipt_refs"] if result else []))
    restore_errors: list[str] = ["conflicting_restore_record"] if any(v["kind"] == "restore" and v["id"] in conflicts for v in all_variants.values()) else []
    restored: list[dict] = []
    for r in rows("restore", False):
        linked = by_id.get(r["data"]["ack_id"])
        if linked is None or linked["id"] in conflicts:
            unresolved.append(r["data"]["ack_id"])
        elif r["binding"] is not None and r["binding"] != expected:
            restore_errors.append("restore_identity_binding_mismatch")
        elif not result or r["data"]["result_digest"] != result["digest"] or (terminal and r["attempt_id"] != terminal["attempt_id"]) or linked["kind"] != "durable_ack":
            restore_errors.append("restore_result_attempt_or_ack_mismatch")
        elif terminal and r["data"]["process_id"] == terminal["data"]["process_id"]:
            restore_errors.append("restore_not_fresh_process")
        elif r in eligible and linked in acks and r["method"] == "FRESH_PROCESS_READBACK" and r["seq"] > linked["seq"] and f["durability"]["status"] == "PASS":
            restored.append(r)
        elif linked and r["seq"] <= linked["seq"]:
            restore_errors.append("restore_precedes_ack")
    f["restoration"] = _finding("FAIL" if restore_errors else "PASS" if restored else "UNKNOWN", restore_errors or (["bound_fresh_process_readback_present"] if restored else ["fresh_process_restoration_not_established"]), ids(rows("restore", False)))
    assessments = rows("support_assessment")
    good_assessments = [r for r in assessments if result and good_terminal and r["data"]["result_digest"] == result["digest"] and r["attempt_id"] == terminal["attempt_id"] and r["method"] == "INDEPENDENT_ASSESSMENT" and r["component"] != terminal["component"]]
    assessment_errors = ["assessment_result_or_attempt_mismatch"] if any(result and (r["data"]["result_digest"] != result["digest"] or (terminal and r["attempt_id"] != terminal["attempt_id"])) for r in assessments) else []
    if any(v["kind"] == "support_assessment" and v["id"] in conflicts for v in all_variants.values()):
        assessment_errors.append("conflicting_support_assessment_record")
    verdicts = sorted({r["data"]["verdict"] for r in good_assessments})
    bound_assessment_history = [r for r in rows("support_assessment", False) if result and terminal and r["binding"] == expected and r["data"]["result_digest"] == result["digest"] and r["attempt_id"] == terminal["attempt_id"] and r["method"] == "INDEPENDENT_ASSESSMENT" and r["component"] != terminal["component"]]
    historical_verdicts = sorted({r["data"]["verdict"] for r in bound_assessment_history})
    if len(historical_verdicts) > 1:
        assessment_errors.append("conflicting_assessments")
    f["support_assessment"] = _finding("FAIL" if assessment_errors else "PASS" if good_assessments else "UNKNOWN", assessment_errors or (["separate_bound_assessment_present_not_truth_certification"] if good_assessments else ["independent_bound_assessment_missing"]), ids(rows("support_assessment", False)))
    # Evidence-class and UI claims cannot strengthen the supplied observations.
    claims = bundle["claims"]
    claim_errors: list[str] = []
    claim_unknown: list[str] = []
    if bundle["evidence_class"] == "OBSERVED_EXECUTION" and (not records or any(r["evidence_class"] != "OBSERVED_EXECUTION" or r["method"] in {"FIXTURE", "LOCAL_SPY", "LOCAL_MEMORY", "SOURCE_REVIEW"} for r in all_variants.values())):
        claim_errors.append("observed_execution_class_overstated")
    runtime = [r for r in rows("runtime_observation") if r["evidence_class"] == "OBSERVED_EXECUTION" and r["method"] == "HTTP" and r["data"]["tree"] == bundle["source"]["tree"] and r["data"]["python"] == bundle["source"]["python"]]
    runtime_errors = []
    if any(v["kind"] == "runtime_observation" and v["id"] in conflicts for v in all_variants.values()):
        runtime_errors.append("conflicting_runtime_record")
    if any(v["kind"] == "runtime_observation" and v["binding"] == expected and (v["data"]["tree"] != bundle["source"]["tree"] or v["data"]["python"] != bundle["source"]["python"]) for v in all_variants.values()):
        runtime_errors.append("runtime_source_or_python_mismatch")
    runtime_ok = bool(runtime) and bundle["evidence_class"] == "OBSERVED_EXECUTION" and "observed_execution_class_overstated" not in claim_errors and not runtime_errors
    f["current_runtime_evidence"] = _finding("FAIL" if runtime_errors else "PASS" if runtime_ok else "UNKNOWN", runtime_errors or (["matching_supplied_runtime_observation_not_live_certification"] if runtime_ok else ["current_runtime_not_observed"]), ids(rows("runtime_observation") + rows("historical_test") + rows("local_contract")))
    for claim, finding in (("durable", "durability"), ("restored", "restoration"), ("current_admission", "admission")):
        if claims[claim] and f[finding]["status"] != "PASS":
            (claim_errors if f[finding]["status"] == "FAIL" else claim_unknown).append(claim + "_claim_not_supported")
    if claims["current_runtime"] and not runtime_ok:
        (claim_errors if runtime_errors else claim_unknown).append("current_runtime_claim_not_supported")
    if claims["deployed"]:
        claim_unknown.append("controller_local_or_deployment_evidence_not_qualified")
    if claims["budget_compliant"] is True and f["budget"]["status"] != "PASS":
        (claim_errors if f["budget"]["status"] == "FAIL" else claim_unknown).append("budget_claim_not_supported")
    if claims["ui_status"] == "finished" and not rows("closure"):
        claim_unknown.append("administrative_closure_not_observed")
    if claims["ui_status"] == "success":
        if outcome in {"FAILURE", "ABSTAINED", "CANCELLED"} or lifecycle_errors or "CONTRADICTED" in verdicts or assessment_errors:
            claim_errors.append("success_projection_contradicted")
        elif outcome != "ANSWER" or verdicts != ["SUPPORTED"]:
            claim_unknown.append("success_projection_not_supported")
    if claims["ui_status"] == "cancelled":
        if outcome in {"ANSWER", "ABSTAINED", "FAILURE"} or lifecycle_errors:
            claim_errors.append("cancelled_projection_contradicts_terminal_outcome")
        elif cancel_state != "STOPPED_FOR_RECORDED_ATTEMPTS_ONLY":
            claim_unknown.append("cancellation_effects_not_established")
    if claims["ui_status"] == "ready_to_orchestrate" and not any(r["data"]["status"] == "READY_TO_ORCHESTRATE" for r in rows("plan")):
        claim_unknown.append("plan_readiness_not_observed")
    if claims["ui_status"] == "abstained" and outcome != "ABSTAINED":
        claim_unknown.append("abstention_not_observed")
    snapshots = rows("legacy_snapshot")
    if snapshots:
        projection = by_id.get(claims["projection_record"])
        if projection is None:
            claim_unknown.append("legacy_final_projection_missing")
        elif projection not in eligible or projection["kind"] != "legacy_snapshot" or projection["data"]["phase"] != "FINAL":
            claim_errors.append("legacy_projection_not_final")
    elif claims["projection_record"] is not None:
        unresolved.append(claims["projection_record"])
        claim_unknown.append("projection_reference_unresolved")
    f["claim_strength"] = _finding("FAIL" if claim_errors else "UNKNOWN" if claim_unknown else "PASS", claim_errors + claim_unknown or ["declared_claims_do_not_exceed_supplied_evidence_scope"], ids(records))
    observations = {
        "evidence_class": bundle["evidence_class"], "wall_clock_bound": "UNKNOWN", "source": bundle["source"].copy(),
        "journey": bundle["journey"].copy(), "unique_record_count": len(records),
        "duplicate_export_count": duplicate_count, "conflicting_record_ids": sorted(conflicts),
        "stale_record_ids": sorted(stale), "outcome": "CONFLICT" if terminal_conflict else outcome,
        "cancellation": cancel_state, "cleanup": sorted({r["data"]["status"] for r in rows("cleanup")}),
        "administrative_closure": ids(rows("closure")), "dispatch_record_ids": ids(rows("dispatch")),
        "attempts": [attempts[k] for k in sorted(attempts)], "charged_or_reserved_cost": charged, "peak_prefix_cost": prefix_peak, "prefix_costs": prefix_costs,
        "unknown_attempt_ids": sorted(k for k, v in attempts.items() if v["state"] == "UNKNOWN"), "unaccounted_attempt_ids": missing_attempts,
        "assessment_verdicts": verdicts, "all_bound_assessment_verdicts": historical_verdicts, "legacy_projections": [{"id": r["id"], **r["data"]} for r in snapshots],
        "signature_integrity_records": ids(rows("signature_integrity")),
        "transport_observations": [{"id": r["id"], **r["data"]} for r in rows("transport")],
        "local_contract_observations": [{"id": r["id"], **r["data"]} for r in rows("local_contract")],
    }
    return {"checker_version": VERSION, "findings": f, "observations": observations, "unresolved_references": sorted(set(unresolved)), "limitations": LIMITATIONS[:]}


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) not in (1, 2):
        print("Usage: python -B observation_checker.py bundle.json [policy.json]", file=sys.stderr)
        return 2
    try:
        def bounded_read(path: str) -> bytes:
            with open(path, "rb") as stream:
                return stream.read(MAX_BYTES + 1)
        report = check_json(bounded_read(args[0]), bounded_read(args[1]) if len(args) == 2 else None)
    except OSError:
        report = _rejected("input:file_unreadable")
    sys.stdout.write(canonical(report))
    # Exit codes describe parser execution only, never aggregate qualification.
    return 2 if report["findings"]["schema"]["status"] == "FAIL" else 0


if __name__ == "__main__":
    raise SystemExit(main())
