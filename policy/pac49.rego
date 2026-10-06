package mcp.pac49

# PAC IDs and meanings follow "정책 최종본의 사본" in the supplied 49-row workbook.
# Only facts assembled by a trusted Gateway/Host may reach this policy.
pack_version := "pac49-v1"

within(now, start, end) if {
    is_number(now)
    is_number(start)
    is_number(end)
    start <= now
    now < end
}

subset(items, allowed) if {
    is_array(items)
    is_array(allowed)
    every item in items { item in allowed }
}

base_valid if {
    input.phase == "request"
    input.facts.trusted == true
    is_number(input.facts.now_ns)
    is_string(input.request.id)
    input.request.id != ""
    is_string(input.request.server_id)
    is_string(input.request.feature_id)
    is_string(input.request.action)
    is_object(input.request.arguments)
    is_boolean(input.request.high_risk)
    is_boolean(input.request.transfer.enabled)
    input.facts.classification.verified == true
    input.request.high_risk == input.facts.classification.high_risk
    input.request.transfer.enabled == input.facts.classification.transfer_required
    input.request.on_behalf_of == input.facts.classification.on_behalf_of
    input.request.automated == input.facts.classification.automated
}

# PAC03: connection approval, conditions, validity and separate user consent.
ok03 if {
    a := input.facts.approval
    a.status == "APPROVED"
    a.server_id == input.request.server_id
    within(input.facts.now_ns, a.valid_from_ns, a.valid_until_ns)
    input.facts.user_consent.verified == true
    input.facts.user_consent.allowed == true
    input.facts.user_consent.server_id == input.request.server_id
    input.facts.user_consent.feature_id == input.request.feature_id
    input.facts.user_consent.asset_id == input.request.data.asset_id
}
ok03 if {
    a := input.facts.approval
    a.status == "CONDITIONAL_APPROVED"
    a.conditions_met == true
    a.server_id == input.request.server_id
    within(input.facts.now_ns, a.valid_from_ns, a.valid_until_ns)
    input.facts.user_consent.verified == true
    input.facts.user_consent.allowed == true
    input.facts.user_consent.server_id == input.request.server_id
    input.facts.user_consent.feature_id == input.request.feature_id
    input.facts.user_consent.asset_id == input.request.data.asset_id
}

# PAC04: approved and separated environment; production data has added controls.
ok04 if {
    e := input.facts.environment
    e.verified == true
    e.id == input.request.environment
    e.id in input.facts.approval.environments
    e.access_separated == true
    e.local_restrictions_verified == true
    e.production_data_used == false
}
ok04 if {
    e := input.facts.environment
    e.verified == true
    e.id == input.request.environment
    e.id in input.facts.approval.environments
    e.access_separated == true
    e.local_restrictions_verified == true
    e.production_data_used == true
    e.responsible_approval == true
    e.production_controls == true
    e.monitoring == true
    e.deletion_plan == true
}

# PAC05 and PAC41: actual endpoint, DNS/redirect/OAuth discovery and changed destination.
ok05 if {
    c := input.facts.connection
    c.verified == true
    c.final_target_verified == true
    c.dns_checked == true
    c.redirect_checked == true
    c.oauth_discovery_checked == true
    c.server_id == input.request.server_id
    some approved in input.facts.approval.connections
    approved.server_id == c.server_id
    approved.endpoint_id == c.endpoint_id
    approved.final_target_id == c.final_target_id
}
ok41 if {
    input.facts.connection.destination_changed == false
}
ok41 if {
    input.facts.connection.destination_changed == true
    input.facts.connection.change_reapproved == true
}

# PAC06: server/type/feature/definition are one approval key.
ok06 if {
    f := input.facts.catalog_feature
    f.verified == true
    f.server_id == input.request.server_id
    f.type == input.request.feature_type
    f.id == input.request.feature_id
    f.definition_hash == input.facts.approval.baseline.feature_definition_hash
    some approved in input.facts.approval.features
    approved.server_id == f.server_id
    approved.type == f.type
    approved.id == f.id
    approved.definition_hash == f.definition_hash
}

# PAC07: the Host/Gateway proves this request passed the managed path.
ok07 if {
    input.facts.gateway.path_verified == true
    input.facts.gateway.direct_connection_blocked == true
    input.facts.gateway.local_execution_blocked == true
}

# PAC08: identity is verified independently of request text.
ok08 if {
    i := input.facts.identity
    a := input.facts.approval.subject
    i.verified == true
    i.user_id == a.user_id
    i.agent_id == a.agent_id
    i.session_id == a.session_id
    input.request.user_id == i.user_id
    input.request.agent_id == i.agent_id
    input.request.session_id == i.session_id
}

# PAC09: delegated use stays within user, agent, purpose and grant.
ok09 if { input.request.on_behalf_of == false }
ok09 if {
    input.request.on_behalf_of == true
    d := input.facts.delegation
    d.verified == true
    d.user_id == input.facts.identity.user_id
    d.agent_id == input.facts.identity.agent_id
    d.purpose_id == input.request.purpose_id
    within(input.facts.now_ns, d.valid_from_ns, d.valid_until_ns)
    input.request.action in d.user_actions
    input.request.action in d.agent_actions
    input.request.action in d.delegated_actions
    input.request.server_id in d.server_ids
    input.request.feature_id in d.feature_ids
}

# PAC10: HTTP OAuth validation, including no token pass-through.
ok10 if {
    input.facts.auth.mode == "local"
    input.facts.auth.verified == true
}
ok10 if {
    t := input.facts.auth
    t.mode == "http"
    t.verified == true
    t.not_revoked == true
    t.not_forwarded == true
    t.issuer == input.facts.approval.auth_issuer
    t.audience == input.request.server_id
    within(input.facts.now_ns, t.valid_from_ns, t.valid_until_ns)
    input.request.action in t.scopes
}

# PAC11: a fresh evaluation is bound to this request.
ok11 if {
    v := input.facts.evaluation
    v.verified == true
    v.fresh == true
    v.request_id == input.request.id
}

# PAC12: action and subject rights are checked for this call.
ok12 if {
    input.facts.action.verified == true
    input.facts.action.normalized == input.request.action
    input.facts.action.kind == input.request.action
    input.request.action in input.facts.approval.actions
    input.request.action in input.facts.identity.allowed_actions
    input.request.action in input.facts.catalog_feature.allowed_actions
}

binding_value(binding) := value if {
    value := object.get(input.request.arguments, binding.argument_path, null)
    value != null
}
binding_valid(binding) if {
    binding.target_type in {"file", "command", "recipient", "url", "object"}
    is_string(binding_value(binding))
    binding_value(binding) != ""
}
binding_valid(binding) if {
    binding.target_type == "scalar"
    binding_value(binding) in binding.allowed_values
}
bound_targets(kind) := {value |
    some binding in input.facts.approval.parameter_bindings
    binding.target_type == kind
    value := binding_value(binding)
}
target_set(items) := {item | item := items[_]}

# PAC13: canonical arguments, complete extraction, schema and target scope.
ok13 if {
    p := input.facts.parameters
    p.verified == true
    p.normalized == true
    p.schema_valid == true
    p.coverage_complete == true
    p.canonical_arguments == input.request.arguments
    p.derived_targets == input.request.targets
    every key, _ in input.request.arguments {
        key in input.facts.approval.allowed_argument_keys
        some binding in input.facts.approval.parameter_bindings
        binding.argument_path[0] == key
    }
    every binding in input.facts.approval.parameter_bindings { binding_valid(binding) }
    target_set(input.request.targets.files) == bound_targets("file")
    target_set(input.request.targets.commands) == bound_targets("command")
    target_set(input.request.targets.recipients) == bound_targets("recipient")
    target_set(input.request.targets.urls) == bound_targets("url")
    target_set(input.request.targets.objects) == bound_targets("object")
    subset(input.request.targets.files, input.facts.approval.targets.files)
    subset(input.request.targets.commands, input.facts.approval.targets.commands)
    subset(input.request.targets.recipients, input.facts.approval.targets.recipients)
    subset(input.request.targets.urls, input.facts.approval.targets.urls)
    subset(input.request.targets.objects, input.facts.approval.targets.objects)
}

# PAC14: asset/grade and all three access scopes.
ok14 if {
    d := input.facts.data
    d.verified == true
    d.asset_id == input.request.data.asset_id
    d.grade == input.request.data.grade
    some approved in input.facts.approval.data_scopes
    approved.asset_id == d.asset_id
    approved.grade == d.grade
    d.asset_id in input.facts.identity.allowed_assets
    d.asset_id in input.facts.delegation.allowed_assets
    d.asset_id in input.facts.catalog_feature.allowed_assets
    some user_scope in input.facts.identity.allowed_data_scopes
    user_scope.asset_id == d.asset_id
    user_scope.grade == d.grade
    some agent_scope in input.facts.delegation.allowed_data_scopes
    agent_scope.asset_id == d.asset_id
    agent_scope.grade == d.grade
    some feature_scope in input.facts.catalog_feature.allowed_data_scopes
    feature_scope.asset_id == d.asset_id
    feature_scope.grade == d.grade
}

# PAC15: transfer destination, purpose, consent and applicable legal review.
ok15 if { input.request.transfer.enabled == false }
transfer_legal_ok if { input.facts.transfer.personal_data == false }
transfer_legal_ok if {
    input.facts.transfer.personal_data == true
    input.facts.transfer.legal_review_passed == true
}
ok15 if {
    input.request.transfer.enabled == true
    x := input.facts.transfer
    x.verified == true
    x.final_destination_verified == true
    x.final_destination_id == input.request.transfer.destination_id
    x.data_grade == input.facts.data.grade
    x.purpose_id == input.request.purpose_id
    x.user_consent_verified == true
    x.consent_destination_id == x.final_destination_id
    x.consent_data_grade == x.data_grade
    transfer_legal_ok
    some pair in input.facts.approval.transfer_pairs
    pair.destination_id == x.final_destination_id
    pair.grade == x.data_grade
    pair.purpose_id == x.purpose_id
}

bound_destination_id := "" if { input.request.transfer.enabled == false }
bound_destination_id := input.facts.transfer.final_destination_id if {
    input.request.transfer.enabled == true
}
approval_binding := {
    "request_id": input.request.id,
    "user_id": input.facts.identity.user_id,
    "agent_id": input.facts.identity.agent_id,
    "session_id": input.facts.identity.session_id,
    "server_id": input.request.server_id,
    "feature_type": input.request.feature_type,
    "feature_id": input.request.feature_id,
    "action": input.request.action,
    "high_risk": input.request.high_risk,
    "on_behalf_of": input.request.on_behalf_of,
    "automated": input.request.automated,
    "purpose_id": input.request.purpose_id,
    "arguments": input.request.arguments,
    "targets": input.request.targets,
    "data": input.request.data,
    "transfer": input.request.transfer,
    "endpoint_id": input.facts.connection.endpoint_id,
    "final_target_id": input.facts.connection.final_target_id,
    "final_destination_id": bound_destination_id,
    "baseline": input.facts.approval.baseline,
}
request_digest := crypto.sha256(json.marshal(approval_binding))
approval_missing if { object.get(input.facts, "individual_approval", null) == null }
ok16 if { input.request.high_risk == false }
ok16 if {
    input.request.high_risk == true
    a := input.facts.individual_approval
    a.verified == true
    a.approver_authorized == true
    a.single_use_reserved == true
    a.status == "APPROVED"
    a.request_id == input.request.id
    a.request_digest == request_digest
    within(input.facts.now_ns, a.valid_from_ns, a.valid_until_ns)
}
approval_needed if {
    input.request.high_risk == true
    approval_missing
    input.facts.approval_workflow_available == true
}

# PAC17: rate, concurrency and time limits; reservation is Gateway-owned.
ok17 if {
    s := input.facts.execution
    l := input.facts.approval.limits
    s.atomic_reservation_verified == true
    s.reservation_request_id == input.request.id
    s.reservation_expires_ns > input.facts.now_ns
    s.rate_within_limit == true
    s.active_concurrency <= l.max_concurrency
    s.total_calls <= l.max_calls
    s.requested_timeout_ms <= l.max_execution_ms
}

# PAC18/19: Host/Gateway must validate external authority and input filtering.
ok18 if {
    input.facts.authority.verified == true
    input.facts.authority.external_content_used_as_grant == false
}
ok19 if {
    input.facts.input_filter.verified == true
    input.facts.input_filter.minimum_necessary == true
    input.facts.input_filter.prohibited_data_removed == true
    input.facts.input_filter.auth_separated == true
}

# PAC21: actual version/definition/schema/policy match approved baseline.
ok21 if {
    b := input.facts.baseline
    a := input.facts.approval.baseline
    b.verified == true
    b.server_version == a.server_version
    b.feature_definition_hash == a.feature_definition_hash
    b.schema_hash == a.schema_hash
    b.policy_version == a.policy_version
}

# PAC23: current suspension/revocation must be clear.
ok23 if {
    r := input.facts.revocation
    r.verified == true
    r.fresh == true
    r.user == false
    r.agent == false
    r.server == false
    r.feature == false
    r.approval == false
}

# PAC36/37: cross-server and cross-task data reuse require explicit scope.
ok36 if { input.request.cross_server_transfer == false }
ok36 if {
    input.request.cross_server_transfer == true
    input.facts.cross_server.verified == true
    input.facts.cross_server.source_server_id != input.request.server_id
    input.facts.cross_server.destination_server_id == input.request.server_id
    input.facts.cross_server.asset_id == input.request.data.asset_id
    input.facts.cross_server.approved == true
}
ok37 if {
    input.facts.context.verified == true
    input.facts.context.isolated == true
    input.facts.context.previous_task_reused == false
}
ok37 if {
    input.facts.context.verified == true
    input.facts.context.previous_task_reused == true
    input.facts.context.reuse_authorized == true
}

# PAC38: scope/volume on one document retrieval.
ok38 if { input.facts.action.kind != "READ" }
ok38 if {
    input.facts.action.kind == "READ"
    input.facts.query_scope.verified == true
    input.facts.query_scope.within_limit == true
}

# PAC39: a repeated mutation must never be forwarded as a fresh call.
ok39 if { not input.facts.action.kind in {"CREATE", "UPDATE", "DELETE"} }
ok39 if {
    input.facts.action.kind in {"CREATE", "UPDATE", "DELETE"}
    input.facts.execution.idempotency_verified == true
    input.facts.execution.duplicate_status == "clear"
    input.facts.execution.previous_mutation_status == "clear"
}

deny contains "PAC03" if { not ok03 }
deny contains "PAC04" if { not ok04 }
deny contains "PAC05" if { not ok05 }
deny contains "PAC06" if { not ok06 }
deny contains "PAC07" if { not ok07 }
deny contains "PAC08" if { not ok08 }
deny contains "PAC09" if { not ok09 }
deny contains "PAC10" if { not ok10 }
deny contains "PAC11" if { not ok11 }
deny contains "PAC12" if { not ok12 }
deny contains "PAC13" if { not ok13 }
deny contains "PAC14" if { not ok14 }
deny contains "PAC15" if { not ok15 }
deny contains "PAC16" if { not ok16; not approval_needed }
deny contains "PAC17" if { not ok17 }
deny contains "PAC18" if { not ok18 }
deny contains "PAC19" if { not ok19 }
deny contains "PAC21" if { not ok21 }
deny contains "PAC23" if { not ok23 }
deny contains "PAC36" if { not ok36 }
deny contains "PAC37" if { not ok37 }
deny contains "PAC38" if { not ok38 }
deny contains "PAC39" if { not ok39 }
deny contains "PAC41" if { not ok41 }

request_findings contains {"policy_id": "INPUT_CONTRACT", "effect": "DENY"} if {
    not base_valid
}
request_findings contains {"policy_id": "POLICY_BUNDLE", "effect": "DENY"} if {
    base_valid
    input.facts.approval.baseline.policy_version != pack_version
}
request_findings contains {"policy_id": id, "effect": "DENY"} if {
    base_valid
    id := deny[_]
}
request_findings contains {"policy_id": "PAC16", "effect": "APPROVAL"} if {
    base_valid
    approval_needed
}

# Response checks run before Tool output enters the Agent or user context.
response_valid if {
    input.phase == "response"
    input.facts.trusted == true
    is_string(input.request.id)
    input.request.id != ""
    input.facts.response.request_id == input.request.id
    input.facts.response.verified == true
}
ok20 if {
    input.facts.response.sensitive_content_checked == true
    input.facts.response.prohibited_data_removed == true
    input.facts.response.access_scope_checked == true
}
ok35 if { input.facts.response.important_document_use == false }
ok35 if {
    input.facts.response.important_document_use == true
    input.facts.response.source_verified == true
    input.facts.response.original_document_matched == true
}
response_findings contains {"policy_id": "INPUT_CONTRACT", "effect": "DENY"} if {
    not response_valid
}
response_findings contains {"policy_id": "POLICY_BUNDLE", "effect": "DENY"} if {
    response_valid
    input.facts.approval.baseline.policy_version != pack_version
}
response_findings contains {"policy_id": "PAC20", "effect": "DENY"} if {
    response_valid
    not ok20
}
response_findings contains {"policy_id": "PAC35", "effect": "DENY"} if {
    response_valid
    not ok35
}
