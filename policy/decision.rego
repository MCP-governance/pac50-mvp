package mcp.decision

findings contains finding if {
    input.phase == "request"
    finding := data.mcp.pac50.request_findings[_]
}
findings contains finding if {
    input.phase == "response"
    finding := data.mcp.pac50.response_findings[_]
}
findings contains finding if {
    input.phase in {"activation", "operation", "retirement"}
    finding := data.mcp.external.findings[_]
}
findings contains {"policy_id": "INPUT_CONTRACT", "effect": "DENY"} if {
    not input.phase in {"request", "response", "activation", "operation", "retirement"}
}

denied_ids := sort([f.policy_id | f := findings[_]; f.effect == "DENY"])
approval_ids := sort([f.policy_id | f := findings[_]; f.effect == "APPROVAL"])

decision := {"effect": "DENY", "policy_ids": denied_ids} if {
    count(denied_ids) > 0
}
decision := {"effect": "APPROVAL", "policy_ids": approval_ids} if {
    count(denied_ids) == 0
    count(approval_ids) > 0
}
decision := {"effect": "ALLOW", "policy_ids": []} if {
    count(findings) == 0
}
