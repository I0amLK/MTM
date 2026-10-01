//! Local schema equivalence and explicitly hypothetical client normalization.
//! These tests do not identify or qualify the live connector's transformation.
use mtm_core::validate_schema_value;
use serde_json::{Value, json};

use super::{schema::object, workflow_schema};

fn submission() -> Value {
    json!({
        "run_id":"run-fixture", "capability":format!("{}.{}", "a".repeat(60), "b".repeat(30)),
        "action":"assessment_complete", "payload":{"route":"compact","label":"数学"},
        "writes":[{"resource":"memory","content":{"text":"line\nvalue"}}],
        "recover_only":false
    })
}

fn legacy_schema(current: &Value) -> Value {
    let properties = current["properties"].clone();
    let mut legacy = object(properties.clone(), &["run_id"]);
    legacy["oneOf"] = json!([
        object(json!({"run_id":properties["run_id"]}), &["run_id"]),
        object(properties, &["run_id", "capability", "action"])
    ]);
    legacy
}

fn valid(value: &Value, schema: &Value) -> bool {
    validate_schema_value(value, schema, "arguments").is_ok()
}

#[test]
fn step_schema_matches_legacy_for_every_field_subset_and_malformed_value() {
    let current = workflow_schema::step();
    let legacy = legacy_schema(&current);
    let complete = submission();
    let fields = ["capability", "action", "payload", "writes", "recover_only"];
    for mask in 0..32 {
        let mut args = json!({"run_id":"run-fixture"});
        for (bit, field) in fields.iter().enumerate() {
            if mask & (1 << bit) != 0 {
                args[field] = complete[field].clone();
            }
        }
        let expected = mask == 0 || mask & 3 == 3;
        assert_eq!(valid(&args, &current), expected, "subset {mask}");
        assert_eq!(valid(&args, &legacy), expected, "legacy subset {mask}");
        for field in [
            "run_id",
            "capability",
            "action",
            "payload",
            "writes",
            "recover_only",
        ] {
            for malformed in [
                Value::Null,
                json!(17),
                json!(""),
                json!([]),
                json!({}),
                json!(true),
            ] {
                let mut changed = args.clone();
                changed[field] = malformed;
                assert_eq!(
                    valid(&changed, &current),
                    valid(&changed, &legacy),
                    "{mask}: {field}"
                );
            }
        }
        for unknown in ["unexpected", "_meta"] {
            let mut changed = args.clone();
            changed[unknown] = json!({});
            assert!(!valid(&changed, &current));
            assert!(!valid(&changed, &legacy));
        }
        if let Some(args) = args.as_object_mut() {
            args.remove("run_id");
        }
        assert!(!valid(&args, &current));
        assert!(!valid(&args, &legacy));
    }
    for writes in [
        json!([{}]),
        json!([{"resource":"memory"}]),
        json!([{"resource":"","content":{}}]),
        json!([{"resource":"memory","content":{},"unexpected":true}]),
        json!([null]),
    ] {
        let mut args = complete.clone();
        args["writes"] = writes;
        assert!(!valid(&args, &current));
        assert!(!valid(&args, &legacy));
    }
}

fn prune_to_properties(input: &Value, schema: &Value) -> Value {
    let mut output = input.clone();
    if let (Some(object), Some(properties)) =
        (output.as_object_mut(), schema["properties"].as_object())
    {
        object.retain(|key, _| properties.contains_key(key));
    }
    output
}

#[test]
fn flat_step_schema_avoids_hypothetical_union_overlap_and_argument_pruning() {
    let current = workflow_schema::step();
    let legacy = legacy_schema(&current);
    let args = submission();
    assert!(valid(&args, &legacy));
    assert!(current.get("oneOf").is_none());
    assert!(current.get("anyOf").is_none());
    assert_eq!(current["additionalProperties"], false);
    assert_eq!(current["required"], json!(["run_id"]));
    for field in ["capability", "action", "payload", "writes", "recover_only"] {
        assert!(current["properties"][field].get("default").is_none());
    }

    // Hypothesis 1: a client relaxes branch-local additionalProperties.
    // This reproduces ambiguity, not evidence that the live client does this.
    let mut relaxed = legacy.clone();
    relaxed["oneOf"][0]["additionalProperties"] = json!(true);
    relaxed["oneOf"][1]["additionalProperties"] = json!(true);
    assert!(valid(&args, &relaxed["oneOf"][0]));
    assert!(valid(&args, &relaxed["oneOf"][1]));
    assert!(!valid(&args, &relaxed));

    // Hypothesis 2: branch-local projection can make both alternatives valid
    // and an anyOf-first repair could silently downgrade submission to fetch.
    let pruned = prune_to_properties(&args, &legacy["oneOf"][0]);
    assert_eq!(pruned, json!({"run_id":"run-fixture"}));
    assert!(valid(&pruned, &legacy["oneOf"][0]));
    assert!(valid(&args, &legacy["oneOf"][1]));

    // A single top-level property surface preserves every field and JSON byte.
    let preserved = prune_to_properties(&args, &current);
    assert_eq!(preserved, args);
    assert_eq!(preserved.to_string(), args.to_string());
    assert!(valid(&preserved, &current));

    // Hypothesis 3: a client materializes advertised top-level defaults.
    // No optional submission default may turn a task fetch into a partial call.
    for mut input in [json!({"run_id":"run-fixture"}), args.clone()] {
        let before = input.clone();
        if let (Some(input), Some(properties)) =
            (input.as_object_mut(), current["properties"].as_object())
        {
            for (key, property) in properties {
                if let Some(default) = property.get("default") {
                    input.entry(key.clone()).or_insert_with(|| default.clone());
                }
            }
        }
        assert_eq!(input, before);
        assert!(valid(&input, &current));
    }

    // _meta in tool arguments is invalid under the old schema too; merely
    // adding it cannot explain the observed multiple-matches error.
    let mut meta = args;
    meta["_meta"] = json!({});
    assert!(!valid(&meta, &legacy["oneOf"][0]));
    assert!(!valid(&meta, &legacy["oneOf"][1]));
    assert!(!valid(&meta, &current));
}
