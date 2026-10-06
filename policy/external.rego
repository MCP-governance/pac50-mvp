package mcp.external

# These rules validate evidence attestations, not the underlying real-world work.
activation_ids := {
    "PAC01", "PAC02", "PAC03", "PAC04", "PAC05", "PAC06",
    "PAC07", "PAC13", "PAC14", "PAC15", "PAC16", "PAC17",
}
operation_ids := {"PAC38", "PAC39", "PAC41", "PAC42", "PAC43"}
retirement_ids := {"PAC45", "PAC46", "PAC47", "PAC48", "PAC49", "PAC50"}

stage_ids := activation_ids if { input.phase == "activation" }
stage_ids := operation_ids if { input.phase == "operation" }
stage_ids := retirement_ids if { input.phase == "retirement" }

base_valid if {
    input.phase in {"activation", "operation", "retirement"}
    input.facts.trusted == true
    is_number(input.facts.now_ns)
    is_string(input.request.server_id)
    input.request.server_id != ""
    is_object(input.facts.attestations)
    input.facts.approval.baseline.policy_version == data.mcp.pac50.pack_version
}

attestation_valid(id) if {
    record := input.facts.attestations[id]
    record.verified == true
    record.passed == true
    record.server_id == input.request.server_id
    is_string(record.evidence_ref)
    record.evidence_ref != ""
    is_number(record.checked_at_ns)
    is_number(record.valid_until_ns)
    record.checked_at_ns <= input.facts.now_ns
    input.facts.now_ns < record.valid_until_ns
}

findings contains {"policy_id": "INPUT_CONTRACT", "effect": "DENY"} if {
    not base_valid
}
findings contains {"policy_id": id, "effect": "DENY"} if {
    base_valid
    id := stage_ids[_]
    not attestation_valid(id)
}
