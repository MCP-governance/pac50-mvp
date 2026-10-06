"""Exercise every Rego control and verify the 50-row catalog boundary."""

import copy
import json
import os
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OPA = os.environ.get("OPA_BIN") or shutil.which("opa")
if not OPA:
    raise SystemExit("OPA CLI not found")

BASE = json.loads((ROOT / "examples" / "allow.json").read_text())
CATALOG = json.loads((ROOT / "catalog" / "controls.json").read_text())


def query(document, rule):
    run = subprocess.run(
        [OPA, "eval", "--format=raw", "-I", "-d", str(ROOT / "policy"), rule],
        input=json.dumps(document),
        text=True,
        capture_output=True,
        check=True,
    )
    raw = run.stdout.strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


def set_path(document, path, value):
    cursor = document
    parts = path.split(".")
    for part in parts[:-1]:
        cursor = cursor[part]
    cursor[parts[-1]] = value


def evaluate(changes=None, phase="request"):
    document = copy.deepcopy(BASE)
    document["phase"] = phase
    if phase in {"activation", "operation", "retirement"}:
        document["facts"]["attestations"] = {}
    for path, value in (changes or {}).items():
        set_path(document, path, value)
    return query(document, "data.mcp.decision.decision")


def expect(name, changes, effect, ids=(), phase="request"):
    actual = evaluate(changes, phase)
    wanted = {"effect": effect, "policy_ids": list(ids)}
    if actual != wanted:
        print(f"FAIL {name}: {actual} != {wanted}")
        return False
    print(f"PASS {name}")
    return True


def main():
    controls = CATALOG["controls"]
    ids = [f"PAC{i:02d}" for i in range(1, 51)]
    assert [c["id"] for c in controls] == ids
    assert [c["source_id"] for c in controls] == [f"POL-{i:02d}" for i in range(1, 51)]
    assert CATALOG["catalog_version"] == "pac50-v1"
    assert all(c["policy"] and c["name"] and c["area"] for c in controls)
    assert sum(c["evaluation"] == "request" for c in controls) == 25
    assert sum(c["evaluation"] == "response" for c in controls) == 2
    assert sum(c["evaluation"] == "external" for c in controls) == 23
    print("PASS catalog: 50 source rows, 25 request, 2 response, 23 external")

    cases = [
        ("normal request", {}, "ALLOW", ()),
        ("PAC08 consent", {"facts.user_consent.allowed": False}, "DENY", ("PAC08",)),
        ("PAC08 consent for another Tool", {
            "facts.user_consent.feature_id": "other"
        }, "DENY", ("PAC08",)),
        ("PAC09 environment separation", {"facts.environment.access_separated": False}, "DENY", ("PAC09",)),
        ("PAC10 DNS", {"facts.connection.dns_checked": False}, "DENY", ("PAC10",)),
        ("PAC11 unknown Tool", {"facts.catalog_feature.id": "other"}, "DENY", ("PAC11",)),
        ("PAC12 Gateway path", {"facts.gateway.path_verified": False}, "DENY", ("PAC12",)),
        ("PAC18 rejected HTTP origin", {"facts.origin.allowed": False}, "DENY", ("PAC18",)),
        ("PAC18 unverified transport", {"facts.connection.transport_verified": False}, "DENY", ("PAC18",)),
        ("PAC18 missing server enforcement", {"facts.origin.server_enforced": False}, "DENY", ("PAC18",)),
        ("PAC18 unapproved origin", {"request.http_origin": "https://unapproved.example.test", "facts.origin.origin": "https://unapproved.example.test"}, "DENY", ("PAC18",)),
        ("PAC18 verified local transport", {"facts.connection.transport": "local", "facts.auth.mode": "local", "facts.origin.allowed": False}, "ALLOW", ()),
        ("PAC19 subject", {"facts.identity.session_id": "other"}, "DENY", ("PAC19",)),
        ("PAC20 delegation purpose", {"facts.delegation.purpose_id": "other"}, "DENY", ("PAC20",)),
        ("PAC21 token forwarding", {"facts.auth.not_forwarded": False}, "DENY", ("PAC21",)),
        ("PAC22 stale evaluation", {"facts.evaluation.fresh": False}, "DENY", ("PAC22",)),
        ("PAC23 action rights", {"facts.identity.allowed_actions": []}, "DENY", ("PAC23",)),
        ("PAC24 invalid input", {"facts.parameters.schema_valid": False}, "DENY", ("PAC24",)),
        ("PAC25 asset rights", {"facts.identity.allowed_assets": []}, "DENY", ("PAC25",)),
        ("PAC25 crossed grade", {
            "facts.identity.allowed_data_scopes": [
                {"asset_id": "asset-1", "grade": "secret"}
            ]
        }, "DENY", ("PAC25",)),
        ("PAC26 unreviewed transfer", {
            "request.transfer.enabled": True,
            "facts.classification.transfer_required": True,
            "request.transfer.destination_id": "dest-1",
            "facts.transfer.personal_data": True,
            "facts.transfer.legal_review_passed": False,
        }, "DENY", ("PAC26",)),
        ("PAC26 approved nonpersonal transfer", {
            "request.transfer.enabled": True,
            "facts.classification.transfer_required": True,
            "request.transfer.destination_id": "dest-1",
            "facts.transfer.personal_data": False,
            "facts.transfer.legal_review_passed": False,
        }, "ALLOW", ()),
        ("PAC27 approval pending", {
            "request.high_risk": True,
            "facts.classification.high_risk": True,
        }, "APPROVAL", ("PAC27",)),
        ("PAC28 rate exceeded", {"facts.execution.rate_within_limit": False}, "DENY", ("PAC28",)),
        ("PAC29 external text used as grant", {
            "facts.authority.external_content_used_as_grant": True
        }, "DENY", ("PAC29",)),
        ("PAC30 prohibited input", {
            "facts.input_filter.prohibited_data_removed": False
        }, "DENY", ("PAC30",)),
        ("PAC37 changed schema", {
            "facts.baseline.schema_hash": "sha256:changed"
        }, "DENY", ("PAC37",)),
        ("PAC44 revoked", {"facts.revocation.server": True}, "DENY", ("PAC44",)),
        ("PAC33 cross-server transfer", {
            "request.cross_server_transfer": True,
            "facts.cross_server.approved": False,
        }, "DENY", ("PAC33",)),
        ("PAC34 context leak", {"facts.context.isolated": False}, "DENY", ("PAC34",)),
        ("PAC35 bulk retrieval", {"facts.query_scope.within_limit": False}, "DENY", ("PAC35",)),
        ("PAC40 changed endpoint", {
            "facts.connection.destination_changed": True,
            "facts.connection.change_reapproved": False,
        }, "DENY", ("PAC40",)),
        ("unknown input source", {"facts.trusted": False}, "DENY", ("INPUT_CONTRACT",)),
        ("wrong policy version", {
            "facts.approval.baseline.policy_version": "pac15-v1"
        }, "DENY", ("PAC37", "POLICY_BUNDLE")),
        ("unknown phase", {}, "DENY", ("INPUT_CONTRACT",), "other"),
        ("normal response", {}, "ALLOW", (), "response"),
        ("PAC31 sensitive output", {
            "facts.response.prohibited_data_removed": False
        }, "DENY", ("PAC31",), "response"),
        ("PAC32 changed document", {
            "facts.response.important_document_use": True,
            "facts.response.source_verified": False,
        }, "DENY", ("PAC32",), "response"),
    ]
    results = [expect(*case) for case in cases]

    high_risk = copy.deepcopy(BASE)
    high_risk["request"]["high_risk"] = True
    high_risk["facts"]["classification"]["high_risk"] = True
    digest = query(high_risk, "data.mcp.pac50.request_digest")
    approval = {
        "verified": True, "approver_authorized": True,
        "single_use_reserved": True, "status": "APPROVED",
        "request_id": "req-001", "request_digest": digest,
        "valid_from_ns": 1700000000000000000,
        "valid_until_ns": 1900000000000000000,
    }
    results.append(expect("PAC27 bound approval", {
        "request.high_risk": True,
        "facts.classification.high_risk": True,
        "facts.individual_approval": approval,
    }, "ALLOW"))
    results.append(expect("PAC27 reused approval", {
        "request.high_risk": True,
        "facts.classification.high_risk": True,
        "facts.individual_approval": dict(approval, single_use_reserved=False),
    }, "DENY", ("PAC27",)))
    results.append(expect("PAC27 changed request", {
        "request.high_risk": True,
        "facts.classification.high_risk": True,
        "request.purpose_id": "other",
        "facts.delegation.purpose_id": "other",
        "facts.individual_approval": approval,
    }, "DENY", ("PAC27",)))
    results.append(expect("PAC36 repeated mutation", {
        "request.action": "UPDATE",
        "facts.action.normalized": "UPDATE",
        "facts.action.kind": "UPDATE",
        "facts.approval.actions": ["READ", "UPDATE"],
        "facts.identity.allowed_actions": ["READ", "UPDATE"],
        "facts.catalog_feature.allowed_actions": ["READ", "UPDATE"],
        "facts.delegation.user_actions": ["READ", "UPDATE"],
        "facts.delegation.agent_actions": ["READ", "UPDATE"],
        "facts.delegation.delegated_actions": ["READ", "UPDATE"],
        "facts.auth.scopes": ["READ", "UPDATE"],
        "facts.execution.duplicate_status": "duplicate",
    }, "DENY", ("PAC36",)))
    results.append(expect("PAC26 consent for another destination", {
        "request.transfer.enabled": True,
        "facts.classification.transfer_required": True,
        "request.transfer.destination_id": "dest-1",
        "facts.transfer.consent_destination_id": "dest-2",
    }, "DENY", ("PAC26",)))
    results.append(expect("PAC36 ambiguous prior mutation", {
        "request.action": "UPDATE",
        "facts.action.normalized": "UPDATE",
        "facts.action.kind": "UPDATE",
        "facts.approval.actions": ["READ", "UPDATE"],
        "facts.identity.allowed_actions": ["READ", "UPDATE"],
        "facts.catalog_feature.allowed_actions": ["READ", "UPDATE"],
        "facts.delegation.user_actions": ["READ", "UPDATE"],
        "facts.delegation.agent_actions": ["READ", "UPDATE"],
        "facts.delegation.delegated_actions": ["READ", "UPDATE"],
        "facts.auth.scopes": ["READ", "UPDATE"],
        "facts.execution.previous_mutation_status": "unknown",
    }, "DENY", ("PAC36",)))

    for phase in ("activation", "operation", "retirement"):
        stage_ids = sorted(
            c["id"] for c in controls if c["attestation_stage"] == phase
        )
        results.append(expect(f"{phase} missing evidence", {}, "DENY", stage_ids, phase))
        record = {
            "verified": True, "passed": True, "server_id": "server-1",
            "evidence_ref": "checked-evidence-id",
            "checked_at_ns": 1700000000000000000,
            "valid_until_ns": 1900000000000000000,
        }
        all_records = {policy_id: dict(record) for policy_id in stage_ids}
        results.append(expect(f"{phase} complete attestations", {
            "facts.attestations": all_records
        }, "ALLOW", (), phase))
        bad_records = copy.deepcopy(all_records)
        bad_records[stage_ids[0]]["server_id"] = "other-server"
        results.append(expect(f"{phase} scope mismatch", {
            "facts.attestations": bad_records
        }, "DENY", (stage_ids[0],), phase))
        stale_records = copy.deepcopy(all_records)
        stale_records[stage_ids[-1]]["valid_until_ns"] = 1800000000000000000
        results.append(expect(f"{phase} expired evidence", {
            "facts.attestations": stale_records
        }, "DENY", (stage_ids[-1],), phase))
    print(f"{sum(results)}/{len(results)} policy cases passed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
