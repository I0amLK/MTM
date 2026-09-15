//! Operation-specific schemas preserve the workflow authority boundary.
//! Top-level properties remain visible to clients that flatten tool schemas.
use serde_json::{Map, Value, json};

use super::schema::{boolean, choice, integer, nonempty, object, strings, text};

fn capability() -> Value {
    json!({"type":"string","minLength":80,"maxLength":8192,
        "pattern":"^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$",
        "description":"Opaque capability from the current envelope for this task domain. Copy unchanged; do not decode, reconstruct or reuse it after replacement/revocation."})
}

fn variant(selector: &str, value: &str, mut properties: Value, required: &[&str]) -> Value {
    properties[selector] = json!({"type":"string","const":value});
    object(properties, required)
}

fn union(selector: &str, variants: Vec<Value>, required: &[&str]) -> Value {
    let mut properties = Map::new();
    let mut values = Vec::new();
    for variant in &variants {
        if let Some(fields) = variant["properties"].as_object() {
            for (name, schema) in fields {
                if name != selector {
                    // Branch schemas own stronger operation-specific constraints.
                    // The union is a display surface, not a second validation authority.
                    properties.entry(name.clone()).or_insert_with(|| {
                        let mut common = schema.clone();
                        if let Some(common) = common.as_object_mut() {
                            common.remove("default");
                            common.remove("const");
                            common.remove("enum");
                        }
                        common
                    });
                }
            }
        }
        if let Some(value) = variant["properties"][selector]["const"].as_str() {
            values.push(value.to_owned());
        }
    }
    values.sort();
    values.dedup();
    properties.insert(selector.to_owned(), json!({"type":"string","enum":values}));
    let mut schema = object(Value::Object(properties), required);
    schema["oneOf"] = Value::Array(variants);
    schema
}

pub(super) fn start() -> Value {
    object(
        json!({
            "problem_id":{"type":"string","default":"problem"},"problem_tex":nonempty(),
            "creation_key":{"type":"string","minLength":16,"maxLength":128,"pattern":"^[A-Za-z0-9_-]+$","description":"Unique identity for one intended creation. Keep the same key and input after a lost response; use a different key for an intentionally independent run."},
            "references":{"type":"array","default":[],"items":object(json!({
                "name":nonempty(),"content":nonempty(),"source":text()
            }), &["name","content"])},
            "register_result":boolean(true),"workflow_mode":{"type":"string","enum":["auto","compact","full"],"default":"auto"},
            "export_path":text(),"project_id":text(),"target_claim_id":text()
        }),
        &["problem_tex"],
    )
}

pub(super) fn step() -> Value {
    let properties = json!({
        "run_id":nonempty(),"capability":capability(),
        "recover_only":{"type":"boolean","default":false,"description":"Only reconcile this exact original submission. Never executes writes or the action. A proven retained prefix or explicitly enrolled atomic action is returned as SUBMISSION_INTERRUPTED; fetch the current task separately and omit retained writes. Opaque, conflicting, unenrolled action and legacy unknown outcomes remain blocked."},
        "action":{"type":"string","minLength":1,"description":"Exact current task.commit_action."},
        "payload":{"type":"object","description":"Match the current task.commit_payload_schema."},
        "writes":{"type":"array","items":object(json!({
            "resource":nonempty(),"content":{"description":"One record matching the current task.write_contract."}
        }), &["resource","content"])}
    });
    let mut schema = object(properties.clone(), &["run_id"]);
    schema["oneOf"] = json!([
        object(json!({"run_id":nonempty()}), &["run_id"]),
        object(properties, &["run_id", "capability", "action"])
    ]);
    schema
}

pub(super) fn inspect() -> Value {
    union(
        "operation",
        vec![
            variant(
                "operation",
                "status",
                json!({"run_id":nonempty()}),
                &["operation", "run_id"],
            ),
            variant(
                "operation",
                "read",
                json!({"capability":capability(),"resource":nonempty()}),
                &["operation", "capability", "resource"],
            ),
            variant(
                "operation",
                "search",
                json!({"capability":capability(),"resource":nonempty(),"query":text(),"limit":integer(1,100,20)}),
                &["operation", "capability", "resource", "query"],
            ),
            variant(
                "operation",
                "projects",
                json!({"limit":integer(1,100,100)}),
                &["operation"],
            ),
            variant(
                "operation",
                "project_status",
                json!({"project_id":nonempty()}),
                &["operation", "project_id"],
            ),
            variant(
                "operation",
                "claim",
                json!({"claim_id":nonempty()}),
                &["operation", "claim_id"],
            ),
            variant(
                "operation",
                "theorem_search",
                json!({"project_id":nonempty(),"query":nonempty(),"limit":integer(1,100,20)}),
                &["operation", "project_id", "query"],
            ),
            variant(
                "operation",
                "dependency_graph",
                json!({"project_id":nonempty()}),
                &["operation", "project_id"],
            ),
            variant(
                "operation",
                "reference_audit",
                json!({"run_id":nonempty()}),
                &["operation", "run_id"],
            ),
        ],
        &["operation"],
    )
}

pub(super) fn retrieve() -> Value {
    let mut paper = variant(
        "operation",
        "paper_search",
        json!({
            "capability":capability(),"query":nonempty(),"author":nonempty(),"title":nonempty(),
            "keywords":nonempty(),"num_results":integer(1,50,10)
        }),
        &["capability", "operation"],
    );
    paper["anyOf"] = json!([{"required":["query"]},{"required":["author"]},{"required":["title"]},{"required":["keywords"]}]);
    let mut schema = union(
        "operation",
        vec![
            variant(
                "operation",
                "theorem_search",
                json!({
                    "capability":capability(),"query":nonempty(),"num_results":integer(1,50,10),
                    "search_intent":{"type":"string","enum":["theorem","construction","example","counterexample","background"],"default":"theorem"}
                }),
                &["capability", "query"],
            ),
            paper,
            variant(
                "operation",
                "paper_lookup",
                json!({"capability":capability(),"query":nonempty()}),
                &["operation", "capability", "query"],
            ),
            variant(
                "operation",
                "theorem_context",
                json!({"capability":capability(),"query":nonempty()}),
                &["operation", "capability", "query"],
            ),
        ],
        &["capability"],
    );
    schema["properties"]["operation"]["default"] = json!("theorem_search");
    schema
}

pub(super) fn control() -> Value {
    union(
        "action",
        vec![
            variant(
                "action",
                "steer",
                json!({"run_id":nonempty(),"message":nonempty()}),
                &["action", "run_id", "message"],
            ),
            variant(
                "action",
                "cancel",
                json!({"run_id":nonempty(),"reason":{"type":"string","default":"user_cancelled"}}),
                &["action", "run_id"],
            ),
            variant(
                "action",
                "project_create",
                json!({"project_id":text(),"title":nonempty(),"metadata":{"type":"object","additionalProperties":true}}),
                &["action", "title"],
            ),
            variant(
                "action",
                "claim_create",
                json!({"project_id":nonempty(),"claim_id":text(),"title":nonempty(),"statement_tex":text(),"conditions":strings(),"metadata":{"type":"object","additionalProperties":true}}),
                &["action", "project_id", "title"],
            ),
            variant(
                "action",
                "claim_revise",
                json!({"claim_id":nonempty(),"statement_tex":nonempty(),"conditions":strings(),"expected_base_revision_id":text()}),
                &["action", "claim_id", "statement_tex"],
            ),
        ],
        &["action"],
    )
}

pub(super) fn artifact() -> Value {
    let projects = choice(&["project_manifest", "project_summary_tex"]);
    let mut schema = union(
        "action",
        vec![
            variant(
                "action",
                "get",
                json!({"run_id":nonempty(),"artifact":choice(&["draft_tex","final_tex","proof_manifest","verification_report","reference_audit","transition_log","debug_manifest"])}),
                &["action", "run_id", "artifact"],
            ),
            variant(
                "action",
                "get",
                json!({"project_id":nonempty(),"artifact":projects.clone()}),
                &["action", "project_id", "artifact"],
            ),
            variant(
                "action",
                "export",
                json!({"run_id":nonempty(),"artifact":{"type":"string","const":"final_tex"},"path":nonempty(),"expected_sha256":text()}),
                &["action", "run_id", "artifact"],
            ),
            variant(
                "action",
                "export",
                json!({"project_id":nonempty(),"artifact":projects,"path":nonempty(),"expected_sha256":text()}),
                &["action", "project_id", "artifact"],
            ),
        ],
        &["action"],
    );
    schema["properties"]["artifact"] = choice(&[
        "draft_tex",
        "final_tex",
        "proof_manifest",
        "verification_report",
        "reference_audit",
        "transition_log",
        "debug_manifest",
        "project_manifest",
        "project_summary_tex",
    ]);
    schema
}
