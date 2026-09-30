//! Fixed current-candidate partial corpus. Read-only proposal, never acceptance.
use crate::{Result, capability, evidence_json, qualify, release_readiness_schema8};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
mod batches;
mod files;
#[cfg(test)]
mod tests;

const CANDIDATE: &str = "13d7890c5c763199ed39295e134ff6cc735ceaa04eaddf6c556431a7a56254f4";
const BASELINE: &str = "f59cbddaebb8b9944d1365d6d4f1c072e2cc78e76dbbce8d870308c470c88034";
const PRODUCT_COMMIT: &str = "7b4afe2359e688263557f62154e4bc1e640c12c0";
const PRODUCT_SOURCE: &str = "0adec4b02a8b54fd20fb30c796c9959ccc346cc0f9336517fc47eafcb6951e02";
const OBS_SOURCE: &str = "10066ff837e2cee485fabe19809f172b1527141195a7fe29488f9fa201b248f0";
const OBS_COMMIT: &str = "b8ca577521f5494c712cd52fb35a611588a32651";
const CORPUS: &str = "9227aa6e199887860d88091467aa53fe45eee55cd337eac0587059f8ec434861";
const PREFIX: &str = "records/evidence/MTM-017/";
const RESEARCH: (&str, &str) = (
    "records/governance/mtm017-research-corpus.json",
    "27aff327aba433e907e3ee639bad5ce0cee1512ba61359bfc2f988c42626eb24",
);
const DRIVER: (&str, &str) = (
    "records/governance/mtm016-release-inputs.json",
    "e55f2c5624e6f94f4805bed38dd968626808f7df00d95bff9168cf86eb8cda04",
);
const PORTABLE: [(&str, &str); 3] = [
    (
        "portable-corpus-20260930-13d7890-r1.json",
        "2eaf96aed03b24994c4cd9b7b4cd1363133de58ab50a06eb91a0028384b38096",
    ),
    (
        "portable-corpus-observation-20260930-13d7890-r1.json",
        "dd78df9247ea44f5883368d7ad2fe7772e57dd04c0e63f54802317bebb49de59",
    ),
    (
        "portable-corpus-independent-review-20260930-13d7890-r1.json",
        "ae3d0bf73d0f2630bd9a153a7509118f6b0a83e723df10cc387d93161fb4d0bc",
    ),
];
const NATIVE: [(&str, &str); 2] = [
    (
        "preview2-corpus-native-13d7890.json",
        "e86e76d01504fbd2e7af78c884e35a433d8de97c81b370450f150b2b829ecfb7",
    ),
    (
        "preview2-qualification-snapshot.json",
        "5018c5b1050cefe6e0ef6c7db0bb0aeb15b03ed492ee8e75d6737097b535d55c",
    ),
];
const U30: [(&str, &str); 5] = [
    (
        "u30-install-sigkill-observations-20260930.json",
        "3adf9eb83394994d31e60cdd55caa3d2c6ef9c822d9a5cd839946dfe78689137",
    ),
    (
        "u30-install-sigkill-independent-review-20260930.json",
        "1151b2bdd4a6296deed7d98159c8f428b3207e140c0adf8f154b4ab9e22e78fc",
    ),
    (
        "u30-install-sigkill-20260930-13d7890-r1.json",
        "76e0cc22e86bd292d94c1c96895a7470f95395ff6c87e8bdda78410428fd5397",
    ),
    (
        "u30-install-sigkill-20260930-13d7890-r2.json",
        "820e728fdd6d895315a593dace4a03a1a529353e61de74c7d41e7bb13ba65bc0",
    ),
    (
        "u30-install-sigkill-20260930-13d7890-r3.json",
        "01e87d752f7aa6ef493df599416d587d410b13d5c6ec7208d7eae2812c2ed64e",
    ),
];
const REVIEW_CHECKS: [&str; 6] = [
    "implementation_and_negative_tests_reviewed",
    "portable_partial_outer_and_forty_five_rows_reviewed",
    "native_fifteen_rows_and_dangerous_u20_reviewed",
    "existing_research_chain_referenced_without_reacceptance",
    "three_distinct_u30_observations_and_seals_reviewed",
    "only_seventy_eight_eligible_twelve_pending_zero_delta",
];

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Reference {
    path: String,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PortableInput {
    raw: Reference,
    observation: Reference,
    review: Reference,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeInput {
    raw: Reference,
    snapshot: Reference,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct U30Input {
    observation: Reference,
    review: Reference,
    trials: Vec<U30Trial>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct U30Trial {
    repeat: u64,
    raw: Reference,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inputs {
    schema: String,
    milestone: String,
    state_schema_version: u64,
    candidate_sha256: String,
    candidate_source_commit: String,
    corpus_sha256: String,
    prepared_by: String,
    portable: PortableInput,
    native: NativeInput,
    research: Reference,
    u30: U30Input,
    corpus_count_incremented: bool,
    production_selector_changed: bool,
    production_state_modified: bool,
    release_qualified: bool,
    deployment_authorized: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputReview {
    schema: String,
    milestone: String,
    inputs_sha256: String,
    implementation_source_sha256: String,
    maintenance_binary_sha256: String,
    prepared_by: String,
    reviewer_session: String,
    decision: String,
    checks: Vec<String>,
    recorded_unix_seconds: u64,
    accepted_delta: u64,
    production_selector_changed: bool,
    production_state_modified: bool,
    release_qualified: bool,
    deployment_authorized: bool,
}
pub(crate) struct Options {
    inputs: String,
    review: String,
}
impl Options {
    pub(crate) fn parse(args: &[String]) -> Result<Self> {
        require(
            args.len() == 4 && args[0] == "--inputs" && args[2] == "--input-review",
            "use corpus-aggregate-check --inputs <repo-relative-json> --input-review <repo-relative-json> only",
        )?;
        Ok(Self {
            inputs: args[1].clone(),
            review: args[3].clone(),
        })
    }
}
fn require(ok: bool, msg: &'static str) -> Result<()> {
    if ok { Ok(()) } else { Err(msg.into()) }
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn marker(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
fn array(v: &Value) -> Result<&Vec<Value>> {
    v.as_array().ok_or_else(|| "aggregate array missing".into())
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_value(evidence_json::decode(bytes)?)
        .map_err(|_| "aggregate closed schema invalid".into())
}
fn anchored(r: &Reference, a: (&str, &str)) -> bool {
    r.path == format!("{PREFIX}{}", a.0) && r.sha256 == a.1
}
fn input_shape(i: &Inputs) -> Result<()> {
    require(
        i.schema == "mtm017-partial-corpus-inputs-v1"
            && i.milestone == "MTM-017"
            && i.state_schema_version == 8
            && i.candidate_sha256 == CANDIDATE
            && i.candidate_source_commit == PRODUCT_COMMIT
            && i.corpus_sha256 == CORPUS
            && marker(&i.prepared_by)
            && !i.corpus_count_incremented
            && !i.production_selector_changed
            && !i.production_state_modified
            && !i.release_qualified
            && !i.deployment_authorized,
        "partial corpus input identity or authority invalid",
    )?;
    require(
        anchored(&i.portable.raw, PORTABLE[0])
            && anchored(&i.portable.observation, PORTABLE[1])
            && anchored(&i.portable.review, PORTABLE[2])
            && anchored(&i.native.raw, NATIVE[0])
            && anchored(&i.native.snapshot, NATIVE[1])
            && i.research.path == RESEARCH.0
            && i.research.sha256 == RESEARCH.1
            && anchored(&i.u30.observation, U30[0])
            && anchored(&i.u30.review, U30[1])
            && i.u30.trials.len() == 3,
        "partial corpus does not select the separately reviewed fixed evidence",
    )?;
    let mut repeats = BTreeSet::new();
    for t in &i.u30.trials {
        require(
            (1..=3).contains(&t.repeat)
                && repeats.insert(t.repeat)
                && anchored(&t.raw, U30[t.repeat as usize + 1]),
            "U30 repeat or raw seal invalid",
        )?;
    }
    Ok(())
}
fn review_shape(
    r: &InputReview,
    i: &Inputs,
    input_sha: &str,
    source: &str,
    binary: &str,
) -> Result<()> {
    require(
        r.schema == "mtm017-partial-corpus-input-review-v1"
            && r.milestone == "MTM-017"
            && r.inputs_sha256 == input_sha
            && r.implementation_source_sha256 == source
            && r.maintenance_binary_sha256 == binary
            && r.prepared_by == i.prepared_by
            && marker(&r.reviewer_session)
            && r.reviewer_session != r.prepared_by
            && r.decision == "approved_for_read_only_proposal"
            && r.checks.iter().map(String::as_str).collect::<Vec<_>>() == REVIEW_CHECKS
            && r.recorded_unix_seconds > 0
            && r.accepted_delta == 0
            && !r.production_selector_changed
            && !r.production_state_modified
            && !r.release_qualified
            && !r.deployment_authorized,
        "independent aggregate input review does not bind this input and implementation",
    )
}
struct Inventory<'a> {
    root: &'a Path,
    entries: BTreeMap<String, (Reference, files::Snapshot, bool)>,
    total: usize,
}
impl<'a> Inventory<'a> {
    fn new(root: &'a Path) -> Self {
        Self {
            root,
            entries: BTreeMap::new(),
            total: 0,
        }
    }
    fn load(&mut self, r: &Reference) -> Result<Vec<u8>> {
        require(hash(&r.sha256), "aggregate seal digest invalid")?;
        if let Some((old, b, _)) = self.entries.get(&r.path) {
            require(old == r, "conflicting aggregate seal")?;
            return Ok(b.bytes.clone());
        }
        let artifact = r.path
            == format!("target/mtm017-preview2/mtm-0.6.0-preview.2-{CANDIDATE}/mtm")
            || r.path == format!("target/mtm017-baselines/mtm-0.6.0-preview.1-{BASELINE}/mtm");
        let flat = r
            .path
            .strip_prefix(PREFIX)
            .is_some_and(|p| !p.contains('/') && p.ends_with(".json"));
        let archived = r
            .path
            .starts_with("target/mtm017-portable-corpus-20260930-13d7890-r1/")
            || r.path
                .starts_with("target/mtm017-u30-sigkill-20260930T084800Z/");
        require(
            flat || archived || artifact || r.path == RESEARCH.0 || r.path == DRIVER.0,
            "aggregate reference outside fixed evidence namespaces",
        )?;
        require(self.entries.len() < 256, "aggregate file count exceeded")?;
        let snapshot = files::read(
            self.root,
            &r.path,
            if artifact {
                32 * 1024 * 1024
            } else {
                1024 * 1024
            },
            artifact,
        )?;
        self.total += snapshot.bytes.len();
        require(self.total <= 64 * 1024 * 1024, "aggregate bytes exceeded")?;
        require(
            digest(&snapshot.bytes) == r.sha256,
            "aggregate sealed bytes changed",
        )?;
        let bytes = snapshot.bytes.clone();
        self.entries
            .insert(r.path.clone(), (r.clone(), snapshot, artifact));
        Ok(bytes)
    }
    fn json(&mut self, r: &Reference) -> Result<Value> {
        evidence_json::decode(&self.load(r)?)
    }
    fn closure(&mut self, v: &Value, depth: usize) -> Result<()> {
        require(depth <= 24, "aggregate reference depth exceeded")?;
        match v {
            Value::Object(m) => {
                if let (Some(path), Some(sha)) = (
                    m.get("path").and_then(Value::as_str),
                    m.get("sha256").and_then(Value::as_str),
                ) {
                    let r = Reference {
                        path: path.into(),
                        sha256: sha.into(),
                    };
                    self.load(&r)?;
                }
                if let (Some(path), Some(sha)) = (
                    m.get("receipt_path").and_then(Value::as_str),
                    m.get("sha256").and_then(Value::as_str),
                ) {
                    self.load(&Reference {
                        path: path.into(),
                        sha256: sha.into(),
                    })?;
                }
                for (key, child) in m {
                    // An archived observation describes the old maintenance executable;
                    // rebuilding this new adapter must not relabel those historical bytes.
                    if key != "maintenance_binary" {
                        self.closure(child, depth + 1)?;
                    }
                }
            }
            Value::Array(a) => {
                for child in a {
                    self.closure(child, depth + 1)?;
                }
            }
            _ => (),
        }
        Ok(())
    }
    fn recheck(&self) -> Result<()> {
        for (r, b, exe) in self.entries.values() {
            b.recheck(&files::read(
                self.root,
                &r.path,
                if *exe { 32 * 1024 * 1024 } else { 1024 * 1024 },
                *exe,
            )?)?;
        }
        Ok(())
    }
}
fn input_bytes(root: &Path, path: &str) -> Result<Vec<u8>> {
    require(
        path.strip_prefix(PREFIX)
            .is_some_and(|p| !p.contains('/') && p.ends_with(".json")),
        "aggregate input or review must be a flat MTM-017 JSON record",
    )?;
    Ok(files::read(root, path, 1024 * 1024, false)?.bytes)
}
#[derive(Serialize)]
struct Row {
    task_id: String,
    repeat: u64,
    status: &'static str,
    batch: &'static str,
    evidence: Option<Reference>,
    observation_id: Option<String>,
}
fn add(
    rows: &mut BTreeMap<(String, u64), Row>,
    task: &str,
    repeat: u64,
    batch: &'static str,
    status: &'static str,
    r: &Reference,
    id: Option<String>,
) -> Result<()> {
    let task_number = task
        .strip_prefix('U')
        .and_then(|x| x.parse::<u64>().ok())
        .ok_or("corpus task invalid")?;
    require(
        task == format!("U{task_number:02}")
            && (1..=30).contains(&task_number)
            && (1..=3).contains(&repeat),
        "corpus cell invalid",
    )?;
    let key = (task.to_owned(), repeat);
    require(!rows.contains_key(&key), "duplicate aggregate cell")?;
    rows.insert(
        key,
        Row {
            task_id: task.into(),
            repeat,
            status,
            batch,
            evidence: Some(r.clone()),
            observation_id: id,
        },
    );
    Ok(())
}
fn finish_rows(mut rows: BTreeMap<(String, u64), Row>) -> Result<Vec<Row>> {
    for task in 26..=29 {
        for repeat in 1..=3 {
            let id = format!("U{task}");
            require(
                !rows.contains_key(&(id.clone(), repeat)),
                "pending corpus cell was promoted",
            )?;
            rows.insert(
                (id.clone(), repeat),
                Row {
                    task_id: id,
                    repeat,
                    status: "pending",
                    batch: "unaccepted_external_scope",
                    evidence: None,
                    observation_id: None,
                },
            );
        }
    }
    require(
        rows.len() == 90,
        "partial corpus coverage is not ninety unique cells",
    )?;
    Ok(rows.into_values().collect())
}
/// Revalidate the already accepted public batch receipts without pretending the
/// old mutable build/archive paths are this implementation. This does not run
/// the original proposal entry, accept rows, or relax its live-source review.
pub(crate) fn archived_public_rows(
    inputs: &Value,
    documents: &BTreeMap<String, Value>,
    research: &Value,
) -> Result<Value> {
    let i: Inputs = serde_json::from_value(inputs.clone())?;
    input_shape(&i)?;
    let get = |r: &Reference| -> Result<&Value> {
        documents
            .get(&r.path)
            .ok_or_else(|| "archived public batch missing".into())
    };
    let portable = batches::portable(
        get(&i.portable.raw)?,
        get(&i.portable.observation)?,
        get(&i.portable.review)?,
        &i.portable,
    )?;
    let native = batches::native(get(&i.native.raw)?, get(&i.native.snapshot)?, &i.native)?;
    let raw = i
        .u30
        .trials
        .iter()
        .map(|t| Ok((t.repeat, t.raw.clone(), get(&t.raw)?.clone())))
        .collect::<Result<Vec<_>>>()?;
    let u30 = batches::u30(get(&i.u30.observation)?, get(&i.u30.review)?, &raw, &i.u30)?;
    let mut rows = BTreeMap::new();
    for v in portable {
        add(
            &mut rows,
            v["task_id"].as_str().ok_or("portable task")?,
            v["repeat"].as_u64().ok_or("portable repeat")?,
            "portable",
            "observed_pass",
            &i.portable.raw,
            None,
        )?;
    }
    for v in native {
        add(
            &mut rows,
            v["task_id"].as_str().ok_or("native task")?,
            v["repeat"].as_u64().ok_or("native repeat")?,
            "native",
            "observed_pass",
            &i.native.raw,
            v["trial_id"].as_str().map(str::to_owned),
        )?;
    }
    let accepted: Reference =
        serde_json::from_value(research["state"]["active_acceptance"].clone())?;
    for v in array(&research["accepted"]["trials"])? {
        add(
            &mut rows,
            v["task_id"].as_str().ok_or("research task")?,
            v["repeat"].as_u64().ok_or("research repeat")?,
            "research",
            "previously_accepted",
            &accepted,
            v["trial_id"].as_str().map(str::to_owned),
        )?;
    }
    for (repeat, seal, id) in u30 {
        add(
            &mut rows,
            "U30",
            repeat,
            "u30",
            "observed_pass",
            &seal,
            Some(id),
        )?;
    }
    Ok(serde_json::to_value(finish_rows(rows)?)?)
}

pub(crate) fn run(root: &Path, options: &Options) -> Result<Value> {
    let source = capability::source_hash(root)?;
    let binary = qualify::digest(&std::env::current_exe()?)?;
    let ib = input_bytes(root, &options.inputs)?;
    let i: Inputs = decode(&ib)?;
    input_shape(&i)?;
    let rb = input_bytes(root, &options.review)?;
    let r: InputReview = decode(&rb)?;
    review_shape(&r, &i, &digest(&ib), &source, &binary)?;
    let mut inv = Inventory::new(root);
    inv.load(&Reference {
        path: DRIVER.0.into(),
        sha256: DRIVER.1.into(),
    })?;
    inv.load(&Reference {
        path: format!("target/mtm017-preview2/mtm-0.6.0-preview.2-{CANDIDATE}/mtm"),
        sha256: CANDIDATE.into(),
    })?;
    let raw = inv.json(&i.portable.raw)?;
    let wrapper = inv.json(&i.portable.observation)?;
    let review = inv.json(&i.portable.review)?;
    let portable = batches::portable(&raw, &wrapper, &review, &i.portable)?;
    inv.closure(&wrapper, 0)?;
    inv.closure(&review, 0)?;
    let nr = inv.json(&i.native.raw)?;
    let snapshot = inv.json(&i.native.snapshot)?;
    let native = batches::native(&nr, &snapshot, &i.native)?;
    inv.closure(&snapshot["report_seals"], 0)?;
    let research = release_readiness_schema8::verified_research_subset(root)?;
    require(
        research["state"]["active_acceptance"]["sha256"]
            == "49fc407487fa7c9104c4a6b7aae92e2cde2b9fe4287bd5c73b0e0352abbaae6e",
        "previous research acceptance changed",
    )?;
    for s in array(&research["sealed_inputs"])? {
        let seal: Reference = serde_json::from_value(s.clone())?;
        inv.load(&seal)?;
    }
    let uw = inv.json(&i.u30.observation)?;
    let ur = inv.json(&i.u30.review)?;
    let mut u30raw = Vec::new();
    for t in &i.u30.trials {
        u30raw.push((t.repeat, t.raw.clone(), inv.json(&t.raw)?));
    }
    let u30 = batches::u30(&uw, &ur, &u30raw, &i.u30)?;
    inv.closure(&uw, 0)?;
    inv.closure(&ur, 0)?;
    let mut rows = BTreeMap::new();
    for v in portable {
        add(
            &mut rows,
            v["task_id"].as_str().ok_or("portable task")?,
            v["repeat"].as_u64().ok_or("portable repeat")?,
            "portable",
            "observed_pass",
            &i.portable.raw,
            None,
        )?;
    }
    for v in native {
        add(
            &mut rows,
            v["task_id"].as_str().ok_or("native task")?,
            v["repeat"].as_u64().ok_or("native repeat")?,
            "native",
            "observed_pass",
            &i.native.raw,
            v["trial_id"].as_str().map(str::to_owned),
        )?;
    }
    let accepted_ref: Reference =
        serde_json::from_value(research["state"]["active_acceptance"].clone())?;
    for v in array(&research["accepted"]["trials"])? {
        add(
            &mut rows,
            v["task_id"].as_str().ok_or("research task")?,
            v["repeat"].as_u64().ok_or("research repeat")?,
            "research",
            "previously_accepted",
            &accepted_ref,
            v["trial_id"].as_str().map(str::to_owned),
        )?;
    }
    for (repeat, seal, id) in u30 {
        add(
            &mut rows,
            "U30",
            repeat,
            "u30",
            "observed_pass",
            &seal,
            Some(id),
        )?;
    }
    let rows = finish_rows(rows)?;
    let covered = rows.iter().filter(|r| r.status != "pending").count();
    let existing = rows
        .iter()
        .filter(|r| r.status == "previously_accepted")
        .count();
    let pending = rows.len() - covered;
    require(
        covered == 78 && existing == 15 && pending == 12,
        "partial corpus scope/count mismatch",
    )?;
    inv.recheck()?;
    require(
        input_bytes(root, &options.inputs)? == ib
            && input_bytes(root, &options.review)? == rb
            && capability::source_hash(root)? == source,
        "aggregate input or source changed",
    )?;
    let seals = inv.entries.values().map(|(s, _, _)| s).collect::<Vec<_>>();
    Ok(
        json!({"schema":"mtm017-partial-corpus-proposal-v1","milestone":"MTM-017","state_schema_version":8,
  "candidate_sha256":CANDIDATE,"candidate_source_commit":PRODUCT_COMMIT,"corpus_sha256":CORPUS,
  "inputs_sha256":digest(&ib),"input_review_sha256":digest(&rb),
  "implementation_source_sha256":source,"maintenance_binary_sha256":binary,"rows":rows,
  "covered_trials":covered,"newly_eligible_trials":covered-existing,"previously_accepted_research_trials":existing,
  "pending_trials":pending,"failed_trials":0,"accepted_delta":0,"newly_accepted_research_trials":0,
  "corpus_count_incremented":false,"corpus_accepted":false,"full_corpus_accepted":false,
  "implementation_complete":"unknown","research_accepted":true,"research_acceptance_scope":"previously_accepted_U21_U25_fifteen_only",
  "release_qualified":false,"deployment_authorized":false,"production_selector_changed":false,"production_state_modified":false,
  "historical_counts_inherited":false,"candidate_executed":false,"trials_reexecuted":false,
  "research_verification":research["verification"],"verified_seals":seals,
  "result_review_required":true,"input_review_cryptographically_authenticated":false,
  "pending_task_ids":["U26","U27","U28","U29"],"u27_u28_mapping_approved":false,
  "limitations":["Only current candidate U01-U25 and U30 observations are proposed; no MTM-016 base is inherited.",
   "The original research pointer is unchanged and its fifteen rows are not accepted again.",
   "Process SIGKILL evidence is not physical power-loss or production-state qualification.",
   "U26-U29 remain twelve pending cells; waivers cannot create corpus rows."]}),
    )
}
