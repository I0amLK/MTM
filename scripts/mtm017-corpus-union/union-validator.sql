-- MTM-017 strictly typed public-evidence governance union, never activation.
INSERT INTO assertion SELECT 'valid bounded JSON objects',
 NOT EXISTS(SELECT 1 FROM docs WHERE body IS NULL OR length(CAST(body AS BLOB))>1048576 OR json_valid(body)=0 OR json_type(body) IS NOT 'object');
INSERT INTO assertion SELECT 'no duplicate keys at any depth',
 NOT EXISTS(SELECT d.id,j.parent,j.key FROM docs d,json_tree(d.body) j
 WHERE j.key IS NOT NULL GROUP BY d.id,j.parent,j.key HAVING count(*)>1);
INSERT INTO assertion SELECT 'structural bounds',
 NOT EXISTS(SELECT d.id FROM docs d,json_tree(d.body) j GROUP BY d.id HAVING count(*)>8192 OR max(length(j.fullkey))>4096);
CREATE TEMP TABLE shapes(pattern TEXT,path TEXT,keys TEXT);
INSERT INTO shapes VALUES
('input','$','schema,milestone,prepared_by,candidate_sha256,maintenance_source_sha256,refs,script,validator_sql,shape_contract,negative_tests,accepted_delta,release_qualified,deployment_authorized,production_selector_changed,production_state_modified'),
('input','$.script','path,sha256'),
('input','$.validator_sql','path,sha256'),
('input','$.negative_tests','path,sha256'),
('u29o%','$','archive_sha256,baseline_exact_restoration_proof,baseline_exact_restoration_proof_sha256,exit_code,finished_at,fixed_diagnostics,helper_sha256,new_captured_working_session_count,original_archive_owner_readonly,original_archive_unchanged,production_modified,production_source_mounted,real_attempt_sequence,real_sanitized_receipts,repetition,rollback_validation_mode,same_old_run_as_original_strict_attempt,schema,selectors_modified,source_capture_repeated,started_at,synthetic_prerequisite_receipts,unprepared_baseline_continuation_claimed,validated_real_rehearsal_passed,working_session_identity_sha256,wrapper_sha256,command_id,command,baseline_exact_restoration_proof_path,operator_decision_path,order_clarification_path,order_clarification_sha256,corpus_import_executed,release_qualified'),
('u29p%','$','schema,archive_sha256,restored_archive_sha256,working_copy_identity_sha256,bytes_and_modes_match,before_baseline_mode_preparation,prepared_modes_used_for_exact_check,synthetic_only'),
('u29_aggregate','$','schema,milestone,observed_on,archive_sha256,source_capture_attempts_total,source_capture_repeated,rollback_validation_mode,original_modes_baseline_continuation,unprepared_baseline_continuation_claimed,successful_independent_real_repetitions,synthetic_prerequisites_counted_as_real,same_original_old_run_preserved,run_id,distinct_commands,distinct_working_sessions,distinct_baseline_working_inodes,distinct_exact_restore_proofs,repetitions,operator_decision,order_clarification,preserved_strict_failure,helper_sha256,wrapper_sha256,corpus_import_executed,readiness_gate_evaluation_performed,release_qualified,production_modified,selectors_modified,original_archive_unchanged,original_archive_owner_readonly,raw_private_state_published,commit_created,pushed'),
('u29_review','$','schema,milestone,reviewed_at,review_type,passed,aggregate,source_free_validation,independent_final_hash_verification_command_id,independent_preexecution_final_hash_check_command_id,verified_real_command_ids,all_verified_real_exit_codes_zero,verified_distinct_real_repetitions,all_same_original_old_run,distinct_commands_sessions_working_inodes_and_exact_proofs,original_archive_unchanged,original_archive_owner_readonly,original_capture_attempts,source_capture_repeated,rollback_validation_mode,unprepared_baseline_continuation_claimed,preserved_strict_failure_sha256,strict_failure_still_failed,operator_decision_sha256,order_clarification_sha256,u29_import_input_review_passed,corpus_import_executed,readiness_gate_evaluation_performed,release_qualified,deployment_authorized_by_this_review,production_modified,selectors_modified,raw_private_state_published,commit_created,pushed'),
('authority_proposal','$','schema,milestone,candidate_sha256,harness_source_sha256,inputs,observed_trials,rows,accepted_delta,corpus_count_incremented,implementation_complete,research_accepted,human_consent_tested,full_corpus_accepted,production_selector_changed,production_state_modified,release_qualified,deployment_authorized'),
('review','$','schema,milestone,decision,reviewer_session,prepared_by,inputs_sha256,script_sha256,validator_sql_sha256,shape_contract_sha256,negative_tests_sha256,maintenance_source_sha256,checks,accepted_delta,release_qualified,deployment_authorized,production_selector_changed,production_state_modified');
CREATE TEMP VIEW objects AS SELECT d.id,s.path,s.keys,json_extract(d.body,s.path) AS body
 FROM docs d JOIN shapes s ON d.id LIKE s.pattern;
INSERT INTO assertion SELECT 'closed root objects with every field',
 NOT EXISTS(SELECT 1 FROM objects o WHERE json_type(o.body) IS NOT 'object'
 OR (SELECT count(*) FROM json_each(o.body)) IS NOT length(o.keys)-length(replace(o.keys,',',''))+1
 OR EXISTS(SELECT 1 FROM json_each(o.body) k WHERE instr(','||o.keys||',',','||k.key||',')=0));
CREATE TEMP TABLE rules(pattern TEXT,path TEXT,kind TEXT,expected TEXT);
INSERT INTO rules VALUES
('input','$.schema','text','mtm017-governance-union-inputs-v1'),('input','$.milestone','text','MTM-017'),
('input','$.prepared_by','text','ctm-corpus-union-session'),
('input','$.candidate_sha256','text','13d7890c5c763199ed39295e134ff6cc735ceaa04eaddf6c556431a7a56254f4'),
('input','$.maintenance_source_sha256','text','e23c984936c6d2945b82db5a0fc26f3ab1ebf4629d7d1bbe14078cca0953620f'),
('input','$.accepted_delta','integer','0'),
('authority_proposal','$.schema','text','mtm017-authority-observation-collection-v1'),
('authority_proposal','$.observed_trials','integer','6'),
('authority_proposal','$.harness_source_sha256','text','e23c984936c6d2945b82db5a0fc26f3ab1ebf4629d7d1bbe14078cca0953620f'),
('authority_proposal','$.accepted_delta','integer','0'),
('base','$.accepted_trials','integer','78'),('base','$.pending_trials','integer','12'),
('base','$.candidate_sha256','text','13d7890c5c763199ed39295e134ff6cc735ceaa04eaddf6c556431a7a56254f4'),
('base','$.candidate_source_commit','text','7b4afe2359e688263557f62154e4bc1e640c12c0'),
('base','$.corpus_sha256','text','9227aa6e199887860d88091467aa53fe45eee55cd337eac0587059f8ec434861'),
('base','$.newly_accepted_nonresearch_trials','integer','63'),
('authority_proposal','$.candidate_sha256','text','13d7890c5c763199ed39295e134ff6cc735ceaa04eaddf6c556431a7a56254f4'),
('base','$.total_trials','integer','90'),('base','$.newly_accepted_research_trials','integer','0'),
('base','$.previously_accepted_research_trials','integer','15'),('base','$.state_schema_version','integer','8'),
('source_gate','$.passed','true',NULL),('source_gate','$.source_identity.unchanged','true',NULL),
('source_gate','$.source_identity.before_sha256','text','e23c984936c6d2945b82db5a0fc26f3ab1ebf4629d7d1bbe14078cca0953620f'),
('source_gate','$.source_identity.after_sha256','text','e23c984936c6d2945b82db5a0fc26f3ab1ebf4629d7d1bbe14078cca0953620f'),
('source_gate','$.tests_skipped_by_preflight','false',NULL),
('regression','$.root_cause','text','indeterminate'),
('regression','$.failed_gate_remains_failed','true',NULL),
('mapping','$.decision_id','text','MTM017-READINESS-DECISION-004'),
('mapping','$.decision','text','approved_contract_pending_observations'),
('state_decision','$.decision_id','text','MTM017-READINESS-DECISION-005'),
('clarification','$.decision_id','text','MTM017-READINESS-DECISION-005-CLARIFICATION-001'),
('u29_aggregate','$.schema','text','mtm017-prepared-copy-rehearsal-observations-v2'),
('u29_aggregate','$.milestone','text','MTM-017'),
('u29_aggregate','$.observed_on','text','2026-09-30'),
('u29_aggregate','$.source_capture_attempts_total','integer','1'),
('u29_aggregate','$.successful_independent_real_repetitions','integer','3'),
('u29_review','$.schema','text','mtm017-prepared-copy-rehearsal-independent-review-v2'),
('u29_review','$.review_type','text','independent_code_and_execution_evidence_review_not_human_witness'),
('u29_review','$.verified_distinct_real_repetitions','integer','3'),
('u29_review','$.original_capture_attempts','integer','1'),
('u29o%','$.schema','text','mtm017-prepared-copy-rehearsal-observation-v2'),
('u29o%','$.exit_code','integer','0'),('u29o%','$.new_captured_working_session_count','integer','1'),
('u29p%','$.schema','text','mtm017-baseline-exact-restoration-v1'),
('review','$.schema','text','mtm017-governance-union-input-review-v1'),
('review','$.milestone','text','MTM-017'),
('review','$.decision','text','approved_for_read_only_governance_union'),
('review','$.reviewer_session','text','review-schema8-importer'),
('review','$.prepared_by','text','ctm-corpus-union-session'),
('review','$.maintenance_source_sha256','text','e23c984936c6d2945b82db5a0fc26f3ab1ebf4629d7d1bbe14078cca0953620f'),
('review','$.accepted_delta','integer','0');
INSERT INTO rules SELECT p.column1,'$.'||j.value,'false',NULL FROM
(VALUES('input'),('base'),('authority_proposal'),('review')) p,
json_each('["production_selector_changed","production_state_modified","release_qualified","deployment_authorized"]') j;
INSERT INTO rules SELECT p.column1,'$.'||j.value,'false',NULL FROM
(VALUES('base'),('authority_proposal')) p,json_each('["full_corpus_accepted"]') j;
INSERT INTO rules SELECT 'authority_proposal','$.'||value,'false',NULL FROM json_each('["corpus_count_incremented","human_consent_tested"]');
INSERT INTO rules SELECT 'u29_aggregate','$.'||value,'true',NULL FROM json_each('["same_original_old_run_preserved","distinct_commands","distinct_working_sessions","distinct_baseline_working_inodes","distinct_exact_restore_proofs","original_archive_unchanged","original_archive_owner_readonly"]');
INSERT INTO rules SELECT 'u29_aggregate','$.'||value,'false',NULL FROM json_each('["source_capture_repeated","original_modes_baseline_continuation","unprepared_baseline_continuation_claimed","synthetic_prerequisites_counted_as_real","corpus_import_executed","readiness_gate_evaluation_performed","release_qualified","production_modified","selectors_modified","raw_private_state_published","commit_created","pushed"]');
INSERT INTO rules SELECT 'u29_review','$.'||value,'true',NULL FROM json_each('["passed","all_verified_real_exit_codes_zero","all_same_original_old_run","distinct_commands_sessions_working_inodes_and_exact_proofs","original_archive_unchanged","original_archive_owner_readonly","strict_failure_still_failed","u29_import_input_review_passed"]');
INSERT INTO rules SELECT 'u29_review','$.'||value,'false',NULL FROM json_each('["source_capture_repeated","unprepared_baseline_continuation_claimed","corpus_import_executed","readiness_gate_evaluation_performed","release_qualified","deployment_authorized_by_this_review","production_modified","selectors_modified","raw_private_state_published","commit_created","pushed"]');
INSERT INTO rules SELECT 'u29o%','$.'||value,'true',NULL FROM json_each('["original_archive_owner_readonly","original_archive_unchanged","same_old_run_as_original_strict_attempt","validated_real_rehearsal_passed"]');
INSERT INTO rules SELECT 'u29o%','$.'||value,'false',NULL FROM json_each('["production_modified","production_source_mounted","selectors_modified","source_capture_repeated","unprepared_baseline_continuation_claimed","corpus_import_executed","release_qualified"]');
INSERT INTO rules SELECT 'u29p%','$.'||value,'true',NULL FROM json_each('["bytes_and_modes_match","before_baseline_mode_preparation"]');
INSERT INTO rules SELECT 'u29p%','$.'||value,'false',NULL FROM json_each('["prepared_modes_used_for_exact_check","synthetic_only"]');
INSERT INTO rules SELECT p.column1,'$.rollback_validation_mode','text','exact_restore_then_prepared_continuation' FROM
(VALUES('u29_aggregate'),('u29_review'),('u29o%')) p;
INSERT INTO assertion SELECT 'required exact scalar types and values',
 NOT EXISTS(SELECT 1 FROM docs d JOIN rules r ON d.id LIKE r.pattern
 WHERE json_type(d.body,r.path) IS NOT r.kind OR (r.expected IS NOT NULL AND CAST(json_extract(d.body,r.path) AS TEXT) IS NOT r.expected));
INSERT INTO assertion SELECT 'input bound to fixed complete inventory',
 (SELECT count(*) FROM json_each((SELECT body FROM docs WHERE id='input'),'$.refs'))=(SELECT count(*) FROM docs WHERE id NOT IN('input','review'))
 AND NOT EXISTS(SELECT 1 FROM docs d WHERE d.id NOT IN('input','review') AND
 (json_extract((SELECT body FROM docs WHERE id='input'),'$.refs.'||d.id||'.path') IS NOT d.path
 OR json_extract((SELECT body FROM docs WHERE id='input'),'$.refs.'||d.id||'.sha256') IS NOT d.sha
 OR (SELECT count(*) FROM json_each((SELECT body FROM docs WHERE id='input'),'$.refs.'||d.id)) IS NOT 2));
INSERT INTO assertion SELECT 'script and SQL input seals',
 json_extract(d.body,'$.script.sha256')=c.script_sha AND json_extract(d.body,'$.validator_sql.sha256')=c.sql_sha
 AND json_extract(d.body,'$.script.path')='target/mtm017-authority-corpus-20260930/union-validator.sh'
 AND json_extract(d.body,'$.validator_sql.path')='target/mtm017-authority-corpus-20260930/union-validator.sql'
 FROM docs d,context c WHERE d.id='input';
INSERT INTO assertion SELECT 'independent review required in propose mode',
 c.testing=1 OR (
 (SELECT count(*) FROM docs WHERE id='review')=1
 AND json_extract(r.body,'$.inputs_sha256')=i.sha
 AND json_extract(r.body,'$.script_sha256')=c.script_sha
 AND json_extract(r.body,'$.validator_sql_sha256')=c.sql_sha
 AND json_extract(r.body,'$.negative_tests_sha256')=json_extract(i.body,'$.negative_tests.sha256')
 AND json_extract(r.body,'$.reviewer_session') IS NOT json_extract(r.body,'$.prepared_by')
 AND json_extract(r.body,'$.checks')='["immutable_seventy_eight_and_research_pointer_checked","six_authority_observations_and_collector_checked","three_real_u29_v2_and_restore_proofs_checked","closed_governance_script_and_negative_tests_checked","unique_ninety_cell_union_zero_delta_checked","source_gate_and_unresolved_failure_scope_preserved"]')
 FROM context c JOIN docs i ON i.id='input' LEFT JOIN docs r ON r.id='review';
CREATE TEMP VIEW receipt AS
 SELECT d.id,1 AS real,j.value AS body FROM docs d,json_each(d.body,'$.real_sanitized_receipts') j WHERE d.id GLOB 'u29o[123]'
 UNION ALL
 SELECT d.id,0,j.value FROM docs d,json_each(d.body,'$.synthetic_prerequisite_receipts') j WHERE d.id GLOB 'u29o[123]';
INSERT INTO assertion SELECT 'one real and one separate prerequisite per trial',
 (SELECT count(*) FROM receipt)=6 AND NOT EXISTS(SELECT 1 FROM docs WHERE id GLOB 'u29o[123]' AND
 (json_type(body,'$.real_sanitized_receipts') IS NOT 'array' OR json_array_length(body,'$.real_sanitized_receipts') IS NOT 1
 OR json_type(body,'$.synthetic_prerequisite_receipts') IS NOT 'array' OR json_array_length(body,'$.synthetic_prerequisite_receipts') IS NOT 1));
CREATE TEMP TABLE receipt_key(key TEXT PRIMARY KEY,kind TEXT,expected TEXT);
INSERT INTO receipt_key SELECT value,'true',NULL FROM json_each('["baseline_disposable_copy_mode_prepared","baseline_mode_preparation_content_unchanged","candidate_restart_resumed","clean_shutdown","exactly_one_transition_per_leg","no_final_artifact_published","old_owner_authenticated","old_run_advanced_on_candidate","original_archive_unchanged","original_bytes_modes_exact_before_baseline_preparation","owner_and_client_sets_unchanged_on_baseline","owner_and_client_sets_unchanged_on_candidate","persisted_signing_key_preserved","rehearsal_complete","restored_archive_bytes_and_modes_match","restored_old_runtime_advanced"]');
INSERT INTO receipt_key SELECT value,'false',NULL FROM json_each('["copied_operator_state_gate_passed","mathematical_verification_claimed","production_modified","production_source_mounted","raw_private_state_published","release_qualified","selectors_modified","unprepared_baseline_continuation_claimed"]');
INSERT INTO receipt_key VALUES
('synthetic_only','conditional',NULL),('archive_sha256','text',NULL),('run_id','text',NULL),
('evidence_kind','text',NULL),('baseline_sha256','text','f59cbddaebb8b9944d1365d6d4f1c072e2cc78e76dbbce8d870308c470c88034'),
('candidate_sha256','text','13d7890c5c763199ed39295e134ff6cc735ceaa04eaddf6c556431a7a56254f4'),
('latex_policy','text','static_only'),('milestone','text','MTM-017'),('native_backend','text','disabled'),
('operator_decision_sha256','text','953be5aa5bfa3632408f66264e129b184219ce09c8ecd5de91ee93e608ee0933'),
('preserved_strict_failure_sha256','text','2fbc819765e920a8ce89ad4f94317a26275b3701c785fe2fa9e2ffee4fbd67d0'),
('rollback_validation_mode','text','exact_restore_then_prepared_continuation'),
('schema','text','mtm017-schema8-copy-rehearsal-v2'),('schema_before','integer','7'),
('schema_candidate','integer','8'),('schema_restored','integer','7');
INSERT INTO assertion SELECT 'closed forty-field receipt shape',
 NOT EXISTS(SELECT 1 FROM receipt r WHERE json_type(r.body) IS NOT 'object' OR (SELECT count(*) FROM json_each(r.body)) IS NOT 40
 OR EXISTS(SELECT 1 FROM json_each(r.body) k WHERE k.key NOT IN(SELECT key FROM receipt_key)));
INSERT INTO assertion SELECT 'strict receipt scalar semantics',
 NOT EXISTS(SELECT 1 FROM receipt r,receipt_key k WHERE
 (k.kind IS NOT 'conditional' AND json_type(r.body,'$.'||k.key) IS NOT k.kind)
 OR (k.expected IS NOT NULL AND CAST(json_extract(r.body,'$.'||k.key) AS TEXT) IS NOT k.expected))
 AND NOT EXISTS(SELECT 1 FROM receipt WHERE
 json_type(body,'$.synthetic_only') IS NOT CASE real WHEN 1 THEN 'false' ELSE 'true' END
 OR json_extract(body,'$.evidence_kind') IS NOT CASE real WHEN 1 THEN 'operator_copy_observation' ELSE 'synthetic_fixture' END);
CREATE TEMP VIEW u29 AS SELECT o.id,CAST(substr(o.id,-1) AS INTEGER) AS repeat,o.path,o.sha,o.body,
 r.body AS receipt,p.body AS proof,p.path AS proof_path,p.sha AS proof_sha
 FROM docs o JOIN receipt r ON r.id=o.id AND r.real=1 JOIN docs p ON p.id='u29p'||substr(o.id,-1)
 WHERE o.id GLOB 'u29o[123]';
INSERT INTO assertion SELECT 'U29 triple and same authorized archive/run',
 count(*)=3 AND count(DISTINCT json_extract(body,'$.command_id'))=3
 AND count(DISTINCT json_extract(body,'$.working_session_identity_sha256'))=3
 AND count(DISTINCT json_extract(proof,'$.working_copy_identity_sha256'))=3
 AND count(DISTINCT proof_sha)=3 AND count(DISTINCT sha)=3
 FROM u29;
INSERT INTO assertion SELECT 'U29 proof, identity and original archive binding',
 NOT EXISTS(SELECT 1 FROM u29 u JOIN docs a ON a.id='u29_aggregate' WHERE
 json_type(u.body,'$.repetition') IS NOT 'integer' OR json_extract(u.body,'$.repetition') IS NOT u.repeat
 OR json_extract(u.body,'$.real_attempt_sequence') IS NOT u.repeat+1
 OR json_extract(u.body,'$.archive_sha256') IS NOT json_extract(a.body,'$.archive_sha256')
 OR json_extract(u.receipt,'$.archive_sha256') IS NOT json_extract(a.body,'$.archive_sha256')
 OR json_extract(u.receipt,'$.run_id') IS NOT json_extract(a.body,'$.run_id')
 OR json_extract(u.proof,'$.archive_sha256') IS NOT json_extract(a.body,'$.archive_sha256')
 OR json_extract(u.proof,'$.restored_archive_sha256') IS NOT json_extract(a.body,'$.archive_sha256')
 OR json_extract(u.body,'$.baseline_exact_restoration_proof_sha256') IS NOT u.proof_sha
 OR json_extract(u.body,'$.baseline_exact_restoration_proof_path') IS NOT u.proof_path
 OR json_extract(u.body,'$.operator_decision_path') IS NOT (SELECT path FROM docs WHERE id='state_decision')
 OR json_extract(u.body,'$.order_clarification_path') IS NOT (SELECT path FROM docs WHERE id='clarification')
 OR json_extract(u.body,'$.order_clarification_sha256') IS NOT (SELECT sha FROM docs WHERE id='clarification')
 OR json_extract(u.body,'$.helper_sha256') IS NOT json_extract(a.body,'$.helper_sha256')
 OR json_extract(u.body,'$.wrapper_sha256') IS NOT json_extract(a.body,'$.wrapper_sha256')
 OR EXISTS(SELECT 1 FROM json_each(u.proof) p LEFT JOIN json_each(u.body,'$.baseline_exact_restoration_proof') q ON p.key=q.key WHERE p.type IS NOT q.type OR p.value IS NOT q.value));
INSERT INTO assertion SELECT 'exact proof embedded shape',
 NOT EXISTS(SELECT 1 FROM u29 WHERE json_type(body,'$.baseline_exact_restoration_proof') IS NOT 'object' OR
 (SELECT count(*) FROM json_each(body,'$.baseline_exact_restoration_proof')) IS NOT 8);
INSERT INTO assertion SELECT 'U29 aggregate repeats point to exact observations',
 json_array_length(a.body,'$.repetitions')=3 AND NOT EXISTS(
 SELECT 1 FROM json_each(a.body,'$.repetitions') j LEFT JOIN u29 u ON json_extract(j.value,'$.repetition')=u.repeat
 WHERE u.id IS NULL OR json_extract(j.value,'$.observation_path') IS NOT u.path OR json_extract(j.value,'$.observation_sha256') IS NOT u.sha
 OR json_extract(j.value,'$.exact_restore_proof_path') IS NOT u.proof_path OR json_extract(j.value,'$.exact_restore_proof_sha256') IS NOT u.proof_sha
 OR json_extract(j.value,'$.command_id') IS NOT json_extract(u.body,'$.command_id')
 OR json_extract(j.value,'$.working_session_identity_sha256') IS NOT json_extract(u.body,'$.working_session_identity_sha256')
 OR json_extract(j.value,'$.started_at') IS NOT json_extract(u.body,'$.started_at') OR json_extract(j.value,'$.finished_at') IS NOT json_extract(u.body,'$.finished_at')
 OR json_type(j.value,'$.passed') IS NOT 'true' OR json_type(j.value,'$.exit_code') IS NOT 'integer' OR json_extract(j.value,'$.exit_code') IS NOT 0)
 FROM docs a WHERE a.id='u29_aggregate';
INSERT INTO assertion SELECT 'valid, separate, ordered U29 UTC windows',
 NOT EXISTS(SELECT 1 FROM u29 WHERE
 json_extract(body,'$.started_at') NOT GLOB '2026-09-30T??:??:??.??????+00:00'
 OR json_extract(body,'$.finished_at') NOT GLOB '2026-09-30T??:??:??.??????+00:00'
 OR unixepoch(json_extract(body,'$.started_at')) IS NULL OR unixepoch(json_extract(body,'$.finished_at')) IS NULL
 OR json_extract(body,'$.started_at')>=json_extract(body,'$.finished_at')
 OR unixepoch(json_extract(body,'$.finished_at'))-unixepoch(json_extract(body,'$.started_at'))>300)
 AND NOT EXISTS(SELECT 1 FROM u29 a,u29 b WHERE a.repeat<b.repeat AND json_extract(a.body,'$.finished_at')>=json_extract(b.body,'$.started_at'));
INSERT INTO assertion SELECT 'state reviewer and real provenance agree',
 json_extract(r.body,'$.aggregate.path')=a.path AND json_extract(r.body,'$.aggregate.sha256')=a.sha
 AND json_array_length(r.body,'$.verified_real_command_ids')=3
 AND NOT EXISTS(SELECT 1 FROM u29 u WHERE json_extract(u.body,'$.command_id') NOT IN(SELECT value FROM json_each(r.body,'$.verified_real_command_ids')))
 AND json_extract(r.body,'$.operator_decision_sha256')=(SELECT sha FROM docs WHERE id='state_decision')
 AND json_extract(r.body,'$.order_clarification_sha256')=(SELECT sha FROM docs WHERE id='clarification')
 AND json_extract(r.body,'$.preserved_strict_failure_sha256')=(SELECT sha FROM docs WHERE id='strict_failure')
 FROM docs r,docs a WHERE r.id='u29_review' AND a.id='u29_aggregate';
INSERT INTO assertion SELECT 'shape and negative-test source bindings',
 json_type(i.body,'$.shape_contract')='object'
 AND (SELECT count(*) FROM json_each(i.body,'$.shape_contract'))=2
 AND json_extract(i.body,'$.shape_contract.path')='target/mtm017-authority-corpus-20260930/union-shapes.sql'
 AND json_extract(i.body,'$.shape_contract.sha256')=c.shape_sha
 AND json_extract(i.body,'$.negative_tests.path')='target/mtm017-authority-corpus-20260930/union-negative-mutations.sql'
 AND json_extract(i.body,'$.negative_tests.sha256')=c.negative_sha
 AND (c.testing=1 OR (json_extract(r.body,'$.shape_contract_sha256')=c.shape_sha AND json_extract(r.body,'$.negative_tests_sha256')=c.negative_sha))
 FROM context c JOIN docs i ON i.id='input' LEFT JOIN docs r ON r.id='review';
INSERT INTO assertion SELECT 'every aggregate repeat one-to-one integer 1..3',
 (SELECT count(DISTINCT json_extract(value,'$.repetition')) FROM json_each(a.body,'$.repetitions'))=3
 AND NOT EXISTS(SELECT 1 FROM json_each(a.body,'$.repetitions')
 WHERE json_type(value,'$.repetition') IS NOT 'integer' OR json_extract(value,'$.repetition') NOT BETWEEN 1 AND 3)
 AND NOT EXISTS(SELECT 1 FROM u29 u WHERE (SELECT count(*) FROM json_each(a.body,'$.repetitions') j WHERE json_extract(j.value,'$.repetition')=u.repeat)<>1)
 FROM docs a WHERE a.id='u29_aggregate';
INSERT INTO assertion SELECT 'U29 hashes are nonempty exact SHA256 strings',
 NOT EXISTS(SELECT 1 FROM docs d,json_tree(d.body) j WHERE d.id GLOB 'u29*'
 AND CAST(j.key AS TEXT) LIKE '%sha256'
 AND (j.type IS NOT 'text' OR length(j.value)<>64 OR j.value GLOB '*[^0-9a-f]*'));
INSERT INTO assertion SELECT 'U29 stable identifier formats',
 NOT EXISTS(SELECT 1 FROM docs d,json_tree(d.body) j WHERE d.id GLOB 'u29*'
 AND j.key IN('run_id','command_id')
 AND (j.type IS NOT 'text' OR length(j.value) NOT BETWEEN 8 AND 160 OR j.value GLOB '*[^A-Za-z0-9_-]*'));
INSERT INTO assertion SELECT 'U29 timestamps cannot normalize invalid clock fields',
 NOT EXISTS(SELECT 1 FROM u29 u,json_each(u.body) j WHERE j.key IN('started_at','finished_at')
 AND (j.type IS NOT 'text' OR CAST(substr(j.value,12,2) AS INTEGER)>23 OR CAST(substr(j.value,15,2) AS INTEGER)>59 OR CAST(substr(j.value,18,2) AS INTEGER)>59));
INSERT INTO assertion SELECT 'public capture limitations remain visible',
 json_type(body,'$.capture_attempts')='integer' AND json_extract(body,'$.capture_attempts')=1
 AND json_type(body,'$.user_quiescence_attested')='true'
 AND json_type(body,'$.source_authorized')='true'
 AND json_type(body,'$.no_recapture_authorized_by_this_receipt')='true'
 AND json_type(body,'$.proc_visibility_complete')='false'
 AND json_type(body,'$.uninspectable_non_mtm_system_process_count')='integer'
 AND json_extract(body,'$.uninspectable_non_mtm_system_process_count')=3
 AND json_type(body,'$.transactional_snapshot_claimed')='false'
 AND json_type(body,'$.capture_receipt.transactional_snapshot_claimed')='false'
 AND json_type(body,'$.capture_receipt.two_source_streams_identical')='true'
 AND json_extract(body,'$.capture_receipt.archive_sha256')=(SELECT json_extract(body,'$.archive_sha256') FROM docs WHERE id='u29_aggregate')
 FROM docs WHERE id='capture';
INSERT INTO assertion SELECT 'final maintenance gate exact four successful checks',
 json_array_length(body,'$.checks')=4
 AND (SELECT count(DISTINCT json_extract(value,'$.name')) FROM json_each(body,'$.checks'))=4
 AND (SELECT count(*) FROM json_each(body,'$.checks') WHERE json_extract(value,'$.name') IN('format','clippy','rust_tests','diff'))=4
 AND NOT EXISTS(SELECT 1 FROM json_each(body,'$.checks') WHERE json_type(value,'$.passed') IS NOT 'true' OR json_type(value,'$.exit_code') IS NOT 'integer' OR json_extract(value,'$.exit_code') IS NOT 0)
 FROM docs WHERE id='source_gate';
INSERT INTO assertion SELECT 'authority collector bound to reviewed inputs',
 json_extract(p.body,'$.inputs.path')=i.path AND json_extract(p.body,'$.inputs.sha256')=i.sha
 FROM docs p,docs i WHERE p.id='authority_proposal' AND i.id='authority_inputs';
CREATE TEMP VIEW base_rows AS SELECT j.value AS body,json_extract(j.value,'$.task_id') AS task_id,
 json_extract(j.value,'$.repeat') AS repeat,json_extract(j.value,'$.status') AS status
 FROM docs d,json_each(d.body,'$.rows') j WHERE d.id='base';
INSERT INTO assertion SELECT 'immutable base ninety unique cells',
 count(*)=90 AND count(DISTINCT task_id||':'||repeat)=90
 AND sum(status='accepted')=78 AND sum(status='pending')=12
 AND sum(status='pending' AND task_id IN('U26','U27','U28','U29'))=12 FROM base_rows;
INSERT INTO assertion SELECT 'base exact cell range and typed repeats',
 NOT EXISTS(SELECT 1 FROM base_rows WHERE task_id IS NOT printf('U%02d',CAST(substr(task_id,2) AS INTEGER))
 OR CAST(substr(task_id,2) AS INTEGER) NOT BETWEEN 1 AND 30 OR repeat NOT BETWEEN 1 AND 3
 OR json_type(body,'$.repeat') IS NOT 'integer' OR status NOT IN('accepted','pending'));
CREATE TEMP VIEW authority AS SELECT j.value AS body,json_extract(j.value,'$.task_id') AS task_id,
 json_extract(j.value,'$.repeat') AS repeat,json_extract(j.value,'$.trial_id') AS observation_id,
 json_extract(j.value,'$.raw') AS evidence FROM docs d,json_each(d.body,'$.rows') j WHERE d.id='authority_proposal';
INSERT INTO assertion SELECT 'six current exact authority observations',
 count(*)=6 AND count(DISTINCT task_id||':'||repeat)=6 AND count(DISTINCT observation_id)=6
 AND sum(task_id IN('U27','U28') AND repeat BETWEEN 1 AND 3)=6
 AND sum(json_type(body,'$.accepted')='false' AND json_extract(body,'$.state')='observed_pass')=6 FROM authority;
CREATE TEMP TABLE new_rows(task_id TEXT,repeat INTEGER,batch TEXT,evidence TEXT,observation_id TEXT,PRIMARY KEY(task_id,repeat));
INSERT INTO new_rows SELECT task_id,repeat,'authority_compatibility_and_boundaries',evidence,observation_id FROM authority;
INSERT INTO new_rows SELECT 'U29',repeat,'operator_copy_exact_restore_then_prepared_continuation',
 json_object('path',path,'sha256',sha),json_extract(body,'$.command_id') FROM u29;
INSERT INTO assertion SELECT 'new nine replace only formerly pending cells',
 (SELECT count(*) FROM new_rows)=9 AND NOT EXISTS(SELECT 1 FROM new_rows n LEFT JOIN base_rows b
 ON n.task_id=b.task_id AND n.repeat=b.repeat WHERE b.status IS NOT 'pending');
CREATE TEMP TABLE union_rows(task_id TEXT,repeat INTEGER,status TEXT,batch TEXT,evidence TEXT,observation_id TEXT,previously_accepted INTEGER,newly_eligible INTEGER,PRIMARY KEY(task_id,repeat));
INSERT INTO union_rows SELECT b.task_id,b.repeat,
 CASE WHEN b.status='accepted' THEN 'previously_accepted' WHEN n.task_id IS NOT NULL THEN 'eligible' ELSE 'pending' END,
 CASE WHEN n.task_id IS NOT NULL THEN n.batch ELSE json_extract(b.body,'$.batch') END,
 CASE WHEN n.task_id IS NOT NULL THEN n.evidence ELSE json_extract(b.body,'$.evidence') END,
 CASE WHEN n.task_id IS NOT NULL THEN n.observation_id ELSE json_extract(b.body,'$.observation_id') END,
 b.status='accepted',n.task_id IS NOT NULL FROM base_rows b LEFT JOIN new_rows n USING(task_id,repeat);
INSERT INTO assertion SELECT '87 union without reaccepting original78 or research15',
 count(*)=90 AND sum(previously_accepted)=78 AND sum(newly_eligible)=9
 AND sum(status='pending')=3 AND sum(status='pending' AND task_id='U26')=3
 AND sum(previously_accepted AND newly_eligible)=0
 AND sum(newly_eligible AND task_id IN('U27','U28'))=6
 AND sum(newly_eligible AND task_id='U29')=3
 AND sum(previously_accepted AND task_id BETWEEN 'U21' AND 'U25')=15 FROM union_rows;
SELECT json_object(
 'schema','mtm017-governance-corpus-union-proposal-v1','milestone','MTM-017',
 'scope','read_only_governance_integration_not_a_Rust_CLI_importer',
 'candidate_sha256','13d7890c5c763199ed39295e134ff6cc735ceaa04eaddf6c556431a7a56254f4',
 'candidate_source_commit','7b4afe2359e688263557f62154e4bc1e640c12c0',
 'candidate_source_sha256','0adec4b02a8b54fd20fb30c796c9959ccc346cc0f9336517fc47eafcb6951e02',
 'maintenance_source_sha256','e23c984936c6d2945b82db5a0fc26f3ab1ebf4629d7d1bbe14078cca0953620f',
 'inputs',json_object('path',i.path,'sha256',i.sha),
 'input_review',json((SELECT json_object('path',path,'sha256',sha) FROM docs WHERE id='review')),
 'script_sha256',c.script_sha,'validator_sql_sha256',c.sql_sha,'shape_contract_sha256',c.shape_sha,'negative_tests_sha256',c.negative_sha,
 'total_cells',(SELECT count(*) FROM union_rows),'previously_accepted_cells',(SELECT sum(previously_accepted) FROM union_rows),
 'newly_eligible_cells',(SELECT sum(newly_eligible) FROM union_rows),'eligible_union_cells',(SELECT count(*) FROM union_rows WHERE status IS NOT 'pending'),
 'pending_cells',(SELECT count(*) FROM union_rows WHERE status='pending'),
 'new_authority_cells',(SELECT count(*) FROM new_rows WHERE task_id IN('U27','U28')),
 'new_operator_copy_cells',(SELECT count(*) FROM new_rows WHERE task_id='U29'),
 'new_research_cells',(SELECT count(*) FROM new_rows WHERE task_id BETWEEN 'U21' AND 'U25'),
 'accepted_delta',0,'corpus_count_incremented',json('false'),
 'implementation_complete','unknown','research_accepted',json('true'),'research_acceptance_scope','unchanged_original_fifteen_only',
 'full_corpus_accepted',json('false'),'release_qualified',json('false'),'deployment_authorized',json('false'),
 'production_selector_changed',json('false'),'production_state_modified',json('false'),
 'private_copy_reopened_by_aggregate',json('false'),'private_research_artifacts_rehashed_by_aggregate',json('false'),
 'original_modes_baseline_continuation',json('false'),'transactional_capture_snapshot_claimed',json('false'),
 'complete_capture_process_visibility_claimed',json('false'),
 'known_source_failure_unresolved',json('true'),'pending_task_ids',json('["U26"]'),
 'rows',json((SELECT json_group_array(json_object('task_id',task_id,'repeat',repeat,'status',status,'batch',batch,
 'evidence',json(evidence),'observation_id',observation_id,
 'previously_accepted',json(CASE previously_accepted WHEN 1 THEN 'true' ELSE 'false' END),
 'newly_eligible',json(CASE newly_eligible WHEN 1 THEN 'true' ELSE 'false' END)))
 FROM (SELECT * FROM union_rows ORDER BY task_id,repeat))),
 'sealed_inputs',json((SELECT json_group_array(json_object('id',id,'path',path,'sha256',sha))
 FROM (SELECT id,path,sha FROM docs WHERE id NOT IN('input','review') ORDER BY id))))
 FROM docs i,context c WHERE i.id='input';
