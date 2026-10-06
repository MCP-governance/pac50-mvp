"""Build OPA input type declarations from the documented example shape."""

import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def shape(value):
    if isinstance(value, dict):
        return {
            "type": "object",
            "properties": {key: shape(item) for key, item in value.items()},
            "additionalProperties": True,
        }
    if isinstance(value, list):
        return {"type": "array", "items": shape(value[0]) if value else {}}
    if isinstance(value, bool):
        return {"type": "boolean"}
    if isinstance(value, int):
        return {"type": "integer"}
    if isinstance(value, float):
        return {"type": "number"}
    return {"type": "string"}


base = json.loads((ROOT / "examples" / "allow.json").read_text())
schema = shape(base)
schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
schema["title"] = "MCP PAC49 decision input"
schema["required"] = ["phase", "request", "facts"]
schema["properties"]["phase"] = {
    "enum": ["request", "response", "activation", "operation", "retirement"]
}
schema["properties"]["request"]["properties"]["id"]["minLength"] = 1
schema["properties"]["facts"]["properties"]["individual_approval"] = shape({
    "verified": True,
    "approver_authorized": True,
    "single_use_reserved": True,
    "status": "APPROVED",
    "request_id": "req-001",
    "request_digest": "hex",
    "valid_from_ns": 1,
    "valid_until_ns": 2,
})
schema["properties"]["facts"]["properties"]["attestations"] = {
    "type": "object",
    "additionalProperties": shape({
        "verified": True,
        "passed": True,
        "server_id": "server-1",
        "evidence_ref": "evidence-id",
        "checked_at_ns": 1,
        "valid_until_ns": 2,
    }),
}
(ROOT / "schema" / "input.schema.json").write_text(
    json.dumps(schema, ensure_ascii=False, indent=2) + "\n"
)
