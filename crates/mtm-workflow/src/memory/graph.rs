use std::collections::{BTreeMap, BTreeSet};

use mtm_contracts::{ErrorCategory, ReCtmError};

pub struct FactGraph {
    predecessors: BTreeMap<String, BTreeSet<String>>,
    successors: BTreeMap<String, BTreeSet<String>>,
    order: Vec<String>,
}

impl FactGraph {
    pub fn new(
        predecessors: BTreeMap<String, BTreeSet<String>>,
        revoked: &BTreeSet<String>,
    ) -> Result<Self, ReCtmError> {
        let mut successors: BTreeMap<String, BTreeSet<String>> = predecessors
            .keys()
            .map(|id| (id.clone(), BTreeSet::new()))
            .collect();
        let mut remaining = BTreeMap::new();
        for (id, dependencies) in &predecessors {
            if revoked.contains(id) {
                return Err(invalid("Revoked fact cannot enter an active graph."));
            }
            for dependency in dependencies {
                if revoked.contains(dependency) || !predecessors.contains_key(dependency) {
                    return Err(invalid("Fact predecessor is missing or revoked."));
                }
                successors
                    .entry(dependency.clone())
                    .or_default()
                    .insert(id.clone());
            }
            remaining.insert(id.clone(), dependencies.len());
        }
        let mut ready = remaining
            .iter()
            .filter(|(_, count)| **count == 0)
            .map(|(id, _)| id.clone())
            .collect::<BTreeSet<_>>();
        let mut order = Vec::with_capacity(predecessors.len());
        while let Some(id) = ready.pop_first() {
            order.push(id.clone());
            if let Some(children) = successors.get(&id) {
                for child in children {
                    let Some(count) = remaining.get_mut(child) else {
                        return Err(invalid("Missing fact node."));
                    };
                    *count -= 1;
                    if *count == 0 {
                        ready.insert(child.clone());
                    }
                }
            }
        }
        if order.len() != predecessors.len() {
            return Err(invalid("Fact graph contains a dependency cycle."));
        }
        Ok(Self {
            predecessors,
            successors,
            order,
        })
    }

    #[must_use]
    pub fn topological_order(&self) -> &[String] {
        &self.order
    }

    #[must_use]
    pub fn descendants(&self, id: &str) -> BTreeSet<String> {
        let mut found = BTreeSet::new();
        let mut pending = vec![id.to_owned()];
        while let Some(next) = pending.pop() {
            if let Some(children) = self.successors.get(&next) {
                for child in children {
                    if found.insert(child.clone()) {
                        pending.push(child.clone());
                    }
                }
            }
        }
        found
    }

    #[must_use]
    pub fn predecessors(&self) -> &BTreeMap<String, BTreeSet<String>> {
        &self.predecessors
    }
}

fn invalid(message: &str) -> ReCtmError {
    ReCtmError::new("FACT_GRAPH_INVALID", message).with_category(ErrorCategory::Validation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_cycle_revocation_and_descendants() -> Result<(), ReCtmError> {
        let graph = FactGraph::new(
            BTreeMap::from([
                ("a".to_owned(), BTreeSet::new()),
                ("b".to_owned(), BTreeSet::from(["a".to_owned()])),
                ("c".to_owned(), BTreeSet::from(["b".to_owned()])),
            ]),
            &BTreeSet::new(),
        )?;
        assert_eq!(graph.topological_order(), &["a", "b", "c"]);
        assert_eq!(
            graph.descendants("a"),
            BTreeSet::from(["b".to_owned(), "c".to_owned()])
        );
        assert!(
            FactGraph::new(
                BTreeMap::from([
                    ("a".to_owned(), BTreeSet::from(["b".to_owned()])),
                    ("b".to_owned(), BTreeSet::from(["a".to_owned()])),
                ]),
                &BTreeSet::new()
            )
            .is_err()
        );
        assert!(
            FactGraph::new(
                graph.predecessors().clone(),
                &BTreeSet::from(["a".to_owned()])
            )
            .is_err()
        );
        Ok(())
    }
}
