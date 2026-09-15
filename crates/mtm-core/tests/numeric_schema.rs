//! Independent range regressions; no reference interpreter or generated oracle.
use mtm_core::validate_schema_value;
use serde_json::{Value, json};

fn valid(value: Value, schema: Value) -> bool {
    validate_schema_value(&value, &schema, "arguments.value").is_ok()
}

#[test]
fn fractional_instances_obey_inclusive_minimum_and_maximum() {
    assert!(!valid(json!(1.5), json!({"type":"number","minimum":3})));
    assert!(!valid(json!(3.5), json!({"type":"number","maximum":3})));
    assert!(!valid(json!(-1.5), json!({"minimum":-1})));
    assert!(!valid(json!(-0.5), json!({"maximum":-1})));
    assert!(valid(json!(1.5), json!({"minimum":1.5,"maximum":1.5})));
    assert!(valid(json!(-0.0), json!({"minimum":0,"maximum":0})));
}

#[test]
fn integer_limits_do_not_round_through_f64() {
    let a = 9_007_199_254_740_992_u64;
    assert!(!valid(json!(a + 1), json!({"maximum":a})));
    assert!(!valid(json!(a), json!({"minimum":a + 1})));
    assert!(!valid(json!(u64::MAX), json!({"maximum":u64::MAX - 1})));
    assert!(!valid(json!(i64::MIN), json!({"minimum":i64::MIN + 1})));
    assert!(valid(
        json!(u64::MAX),
        json!({"minimum":u64::MAX,"maximum":u64::MAX})
    ));
    assert!(valid(
        json!(i64::MIN),
        json!({"minimum":i64::MIN,"maximum":i64::MIN})
    ));
}

#[test]
fn mixed_numeric_bounds_preserve_fraction_and_large_integer_order() {
    assert!(!valid(json!(1), json!({"minimum":1.5})));
    assert!(!valid(json!(-1), json!({"maximum":-1.5})));
    assert!(valid(json!(-1), json!({"minimum":-1.5})));
    assert!(valid(json!(1), json!({"maximum":1.5})));
    assert!(!valid(
        json!(9_007_199_254_740_993_u64),
        json!({"maximum":9_007_199_254_740_992.0})
    ));
    assert!(!valid(
        json!(9_007_199_254_740_992.0),
        json!({"minimum":9_007_199_254_740_993_u64})
    ));
    assert!(valid(
        json!(u64::MAX),
        json!({"maximum":18_446_744_073_709_551_616.0})
    ));
    assert!(!valid(
        json!(18_446_744_073_709_551_616.0),
        json!({"maximum":u64::MAX})
    ));
    assert!(valid(json!(i64::MIN), json!({"minimum":-1e100})));
    assert!(!valid(json!(-1e100), json!({"minimum":i64::MIN})));
}

#[test]
fn non_numeric_bounds_fail_closed_and_errors_locate_the_field() {
    for bound in [Value::Null, json!(true), json!("3"), json!([])] {
        let error = validate_schema_value(&json!(2), &json!({"minimum":bound}), "arguments.count");
        assert_eq!(error.map_err(|e| e.code), Err("SCHEMA_INVALID".to_owned()));
    }
    let error = validate_schema_value(&json!(2.5), &json!({"minimum":3}), "arguments.count");
    assert_eq!(
        error.map_err(|e| e.message),
        Err("arguments.count must be >= 3".to_owned())
    );
}

#[test]
fn small_mixed_grid_matches_exact_quarter_units() {
    for integer in -8_i64..=8 {
        for numerator in -33_i64..=33 {
            let fraction = numerator as f64 / 4.0;
            assert_eq!(
                valid(json!(integer), json!({"minimum":fraction})),
                integer * 4 >= numerator
            );
            assert_eq!(
                valid(json!(integer), json!({"maximum":fraction})),
                integer * 4 <= numerator
            );
            assert_eq!(
                valid(json!(fraction), json!({"minimum":integer})),
                numerator >= integer * 4
            );
            assert_eq!(
                valid(json!(fraction), json!({"maximum":integer})),
                numerator <= integer * 4
            );
        }
    }
}
