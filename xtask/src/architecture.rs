use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

use crate::Result;

pub(crate) fn validate(root: &Path) -> Result<Value> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .args(["metadata", "--no-deps", "--format-version", "1", "--locked"])
        .current_dir(root)
        .stdin(Stdio::null())
        .output()?;
    if !output.status.success() || output.stdout.len() > 8 * 1024 * 1024 {
        return Err("bounded Cargo metadata query failed".into());
    }
    let metadata: Value = serde_json::from_slice(&output.stdout)?;
    let graph: Value = serde_json::from_slice(&fs::read(
        root.join("records/governance/engineering-graph.json"),
    )?)?;
    validate_metadata(&metadata, &graph["crate_dependency_graph"])
}

fn validate_metadata(metadata: &Value, graph: &Value) -> Result<Value> {
    let vertices = graph["vertices"]
        .as_array()
        .ok_or("missing crate vertices")?;
    let mut product = BTreeSet::new();
    for vertex in vertices {
        if !product.insert(vertex["id"].as_str().ok_or("missing crate id")?) {
            return Err("duplicate crate vertex".into());
        }
    }
    let mut expected = BTreeSet::new();
    for edge in graph["edges"].as_array().ok_or("missing crate edges")? {
        let source = edge["source"].as_str().ok_or("missing edge source")?;
        let target = edge["target"].as_str().ok_or("missing edge target")?;
        if !product.contains(source)
            || !product.contains(target)
            || !expected.insert((source, target))
        {
            return Err("invalid or duplicate crate edge".into());
        }
    }
    let mut actual = BTreeSet::new();
    let mut packages = BTreeSet::new();
    for package in metadata["packages"].as_array().ok_or("missing packages")? {
        let name = package["name"].as_str().ok_or("missing package name")?;
        if !packages.insert(name) || (!product.contains(name) && name != "mtm-xtask") {
            return Err("unexpected or duplicate workspace package".into());
        }
        for dependency in package["dependencies"]
            .as_array()
            .ok_or("missing dependencies")?
        {
            let target = dependency["name"]
                .as_str()
                .ok_or("missing dependency name")?;
            if name != "mtm-xtask" && target == "mtm-xtask" {
                return Err("product must not depend on maintenance tooling".into());
            }
            if name == "mtm-xtask" && product.contains(target) {
                return Err(
                    "initial maintenance tool must remain independent of product runtime".into(),
                );
            }
            if product.contains(target) && dependency["kind"].is_null() {
                actual.insert((name, target));
            }
        }
    }
    let mut expected_packages = product.clone();
    expected_packages.insert("mtm-xtask");
    if packages != expected_packages || actual != expected {
        return Err(format!(
            "Cargo graph differs: missing_edges={:?}, undeclared_edges={:?}, missing_packages={:?}, unexpected_packages={:?}",
            expected.difference(&actual).collect::<Vec<_>>(),
            actual.difference(&expected).collect::<Vec<_>>(),
            expected_packages.difference(&packages).collect::<Vec<_>>(),
            packages.difference(&expected_packages).collect::<Vec<_>>(),
        ).into());
    }
    Ok(
        json!({"ok":true,"product_crates":product.len(),"product_edges":actual.len(),"maintenance_crates":1,"reverse_maintenance_dependency":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Value, Value) {
        (
            json!({"packages":[{"name":"mtm-core","dependencies":[]},{"name":"mtm-xtask","dependencies":[]}]}),
            json!({"vertices":[{"id":"mtm-core"}],"edges":[]}),
        )
    }

    #[test]
    fn maintenance_is_not_a_product_dependency() -> Result<()> {
        let (mut metadata, graph) = fixture();
        assert_eq!(validate_metadata(&metadata, &graph)?["product_crates"], 1);
        metadata["packages"][0]["dependencies"] = json!([{"name":"mtm-xtask","kind":"dev"}]);
        assert!(validate_metadata(&metadata, &graph).is_err());
        Ok(())
    }

    #[test]
    fn unknown_packages_and_missing_edges_are_rejected() {
        let (mut metadata, mut graph) = fixture();
        metadata["packages"][0]["name"] = json!("unexpected");
        assert!(validate_metadata(&metadata, &graph).is_err());
        let (metadata, _) = fixture();
        graph["edges"] = json!([{"source":"mtm-core","target":"missing"}]);
        assert!(validate_metadata(&metadata, &graph).is_err());
    }
}
