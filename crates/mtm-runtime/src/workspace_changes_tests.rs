use super::*;

fn setup() -> Result<(tempfile::TempDir, tempfile::TempDir, NativeWorkspace), ReCtmError> {
    let root = tempfile::tempdir().map_err(io_error)?;
    let private = tempfile::tempdir().map_err(io_error)?;
    let workspace = NativeWorkspace::new(root.path(), private.path())?;
    Ok((root, private, workspace))
}
fn args(v: Value) -> Result<Map<String, Value>, ReCtmError> {
    v.as_object()
        .cloned()
        .ok_or_else(|| internal("test object"))
}
fn apply(w: &NativeWorkspace, v: Value) -> Result<Value, ReCtmError> {
    let (p, _) = prepare(w, &args(v)?)?;
    w.commit_prepared_patch_with_authorization(p, || Ok(()))
}
fn revision(s: &str) -> String {
    sha256_bytes(s.as_bytes())
}

#[test]
fn all_six_actions_are_revision_bound_and_copy_does_not_touch_source() -> Result<(), ReCtmError> {
    let (root, _private, w) = setup()?;
    apply(
        &w,
        json!({"changes":[{"action":"create","path":"a","content":"one\ntwo\n"}]}),
    )?;
    let source = root.path().join("a");
    let inode = fs::metadata(&source).map_err(io_error)?.ino();
    let copied = apply(
        &w,
        json!({"changes":[{"action":"copy","path":"a","revision":revision("one\ntwo\n"),"destination":"b"}]}),
    )?;
    assert_eq!(fs::metadata(&source).map_err(io_error)?.ino(), inode);
    assert_eq!(copied["affected_files"].as_array().map(Vec::len), Some(1));
    apply(
        &w,
        json!({"changes":[{"action":"edit","path":"b","revision":revision("one\ntwo\n"),"edits":[{"op":"replace","start_line":2,"content":"three"}]}]}),
    )?;
    assert_eq!(
        fs::read_to_string(root.path().join("b")).map_err(io_error)?,
        "one\nthree\n"
    );
    apply(
        &w,
        json!({"changes":[{"action":"move","path":"b","revision":revision("one\nthree\n"),"destination":"c"}]}),
    )?;
    assert!(!root.path().join("b").exists());
    apply(
        &w,
        json!({"changes":[{"action":"write","path":"c","revision":revision("one\nthree\n"),"content":"final"}]}),
    )?;
    apply(
        &w,
        json!({"changes":[{"action":"delete","path":"c","revision":revision("final")}]}),
    )?;
    assert!(!root.path().join("c").exists());
    Ok(())
}

#[test]
fn stale_revision_alias_collision_and_existing_destination_never_write() -> Result<(), ReCtmError> {
    let (root, _private, w) = setup()?;
    fs::write(root.path().join("a"), "one").map_err(io_error)?;
    fs::write(root.path().join("b"), "two").map_err(io_error)?;
    for changes in [
        json!([{"action":"write","path":"a","revision":revision("stale"),"content":"bad"}]),
        json!([{"action":"delete","path":"a"}]),
        json!([{"action":"move","path":"a","revision":revision("one"),"destination":"b"}]),
        json!([{"action":"write","path":"a","revision":revision("one"),"content":"bad"},{"action":"delete","path":"./a","revision":revision("one")}]),
        json!([{"action":"create","path":"new","content":"x"},{"action":"delete","path":"missing","revision":revision("x")}]),
    ] {
        assert!(apply(&w, json!({"changes":changes})).is_err());
    }
    assert_eq!(
        fs::read_to_string(root.path().join("a")).map_err(io_error)?,
        "one"
    );
    assert_eq!(
        fs::read_to_string(root.path().join("b")).map_err(io_error)?,
        "two"
    );
    assert!(!root.path().join("new").exists());
    Ok(())
}

#[test]
fn dry_run_noop_and_copy_dependency_have_no_source_side_effects() -> Result<(), ReCtmError> {
    let (root, _private, w) = setup()?;
    fs::write(root.path().join("a"), "one").map_err(io_error)?;
    let old = fs::metadata(root.path().join("a")).map_err(io_error)?.ino();
    let no_op = apply(
        &w,
        json!({"changes":[{"action":"write","path":"a","revision":revision("one"),"content":"one"}]}),
    )?;
    assert_eq!(no_op["already_applied"], true);
    assert_eq!(no_op["additions"], 0);
    assert_eq!(
        fs::metadata(root.path().join("a")).map_err(io_error)?.ino(),
        old
    );
    let dry = apply(
        &w,
        json!({"dry_run":true,"changes":[{"action":"create","path":"dir/new","content":"x"}]}),
    )?;
    assert_eq!(dry["dry_run"], true);
    assert!(!root.path().join("dir").exists());
    let (p, _) = prepare(
        &w,
        &args(
            json!({"changes":[{"action":"copy","path":"a","revision":revision("one"),"destination":"b"}]}),
        )?,
    )?;
    let result = w.commit_prepared_patch_with_authorization(p, || {
        fs::write(root.path().join("a"), "changed").map_err(io_error)
    });
    assert!(result.is_err());
    assert!(!root.path().join("b").exists());
    Ok(())
}

#[test]
fn line_edits_preserve_crlf_bom_eof_and_original_numbering() -> Result<(), ReCtmError> {
    let edit = |v| serde_json::from_value::<Vec<LineEdit>>(v).map_err(|_| validation("fixture"));
    assert_eq!(
        edit_lines(
            "\u{feff}a\r\nb\r\nc\r\n",
            &edit(json!([
                {"op":"replace","start_line":2,"content":"x\r\ny"},
                {"op":"insert_after","line":3,"content":"z"}
            ]))?
        )?,
        "\u{feff}a\r\nx\r\ny\r\nc\r\nz\r\n"
    );
    assert_eq!(
        edit_lines(
            "a\rb",
            &edit(json!([{"op":"replace","start_line":1,"content":"x"}]))?
        )?,
        "x"
    );
    assert_eq!(
        edit_lines(
            "last",
            &edit(json!([{"op":"insert_before","line":1,"content":"first"}]))?
        )?,
        "first\nlast"
    );
    assert!(edit_lines("a\nb\n",&edit(json!([{"op":"delete","start_line":1,"end_line":2},{"op":"insert_after","line":1,"content":"x"}]))?).is_err());
    Ok(())
}

#[test]
fn private_symlink_hardlink_and_large_source_are_rejected() -> Result<(), ReCtmError> {
    use std::os::unix::fs::symlink;
    let (root, private, w) = setup()?;
    fs::write(private.path().join("secret"), "private").map_err(io_error)?;
    symlink(private.path().join("secret"), root.path().join("sym")).map_err(io_error)?;
    fs::hard_link(private.path().join("secret"), root.path().join("hard")).map_err(io_error)?;
    for path in ["sym", "hard", "../escape"] {
        assert!(apply(&w,json!({"changes":[{"action":"copy","path":path,"revision":revision("private"),"destination":"copy"}]})).is_err());
    }
    let f = fs::File::create(root.path().join("large")).map_err(io_error)?;
    f.set_len((MAX_BYTES + 1) as u64).map_err(io_error)?;
    assert!(
        apply(
            &w,
            json!({"changes":[{"action":"delete","path":"large","revision":"a".repeat(64)}]})
        )
        .is_err()
    );
    assert!(!root.path().join("copy").exists());
    Ok(())
}

#[test]
fn failed_batch_rolls_back_and_drifted_backup_is_not_claimed_restored() -> Result<(), ReCtmError> {
    let (root, _private, w) = setup()?;
    for (path, text) in [("a", "one"), ("b", "two")] {
        fs::write(root.path().join(path), text).map_err(io_error)?;
    }
    let request = json!({"changes":[
        {"action":"write","path":"a","revision":revision("one"),"content":"new one"},
        {"action":"write","path":"b","revision":revision("two"),"content":"new two"}
    ]});
    let (p, _) = prepare(&w, &args(request.clone())?)?;
    let result = w.commit_prepared_patch_with_hook(
        p,
        || Ok(()),
        |i| {
            if i == 1 {
                Err(internal("injected"))
            } else {
                Ok(())
            }
        },
    );
    assert!(result.is_err());
    assert_eq!(
        fs::read_to_string(root.path().join("a")).map_err(io_error)?,
        "one"
    );
    let mut held = OpenOptions::new()
        .write(true)
        .open(root.path().join("a"))
        .map_err(io_error)?;
    let (p, _) = prepare(&w, &args(request)?)?;
    let result = w.commit_prepared_patch_with_hook(
        p,
        || Ok(()),
        |i| {
            if i == 1 {
                held.write_all(b"BAD").map_err(io_error)?;
                Err(internal("injected"))
            } else {
                Ok(())
            }
        },
    );
    assert_eq!(
        result.map_err(|e| e.code),
        Err("NATIVE_PATCH_ROLLBACK_FAILED".into())
    );
    assert_ne!(
        fs::read_to_string(root.path().join("a")).map_err(io_error)?,
        "BAD"
    );
    Ok(())
}

#[test]
fn bom_mixed_endings_and_precise_edit_evidence() -> Result<(), ReCtmError> {
    let (root, _private, w) = setup()?;
    for (old, replacement, expected) in [("\u{feff}", "x", "\u{feff}x"), ("a", "b\n", "b\n\n")] {
        fs::write(root.path().join("a"), old).map_err(io_error)?;
        let result = apply(
            &w,
            json!({"changes":[{"action":"edit","path":"a","revision":revision(old),"edits":[{"op":"replace","start_line":1,"content":replacement}]}]}),
        )?;
        assert_eq!(
            fs::read_to_string(root.path().join("a")).map_err(io_error)?,
            expected
        );
        assert_eq!(
            result["affected_files"][0]["total_lines"],
            count_lines(expected)
        );
        assert_eq!(result["additions"], count_lines(expected));
        assert_eq!(result["removals"], 1);
    }
    let old = "a\r\nb\nc\r\n";
    fs::write(root.path().join("a"), old).map_err(io_error)?;
    let result = apply(
        &w,
        json!({"changes":[{"action":"edit","path":"a","revision":revision(old),"edits":[{"op":"replace","start_line":2,"content":"b"}]}]}),
    )?;
    assert_eq!(result["already_applied"], true);
    assert_eq!(
        fs::read_to_string(root.path().join("a")).map_err(io_error)?,
        old
    );
    let result = apply(
        &w,
        json!({"changes":[{"action":"edit","path":"a","revision":revision(old),"edits":[{"op":"replace","start_line":2,"content":"x"}]}]}),
    )?;
    assert_eq!(result["additions"], 1);
    assert_eq!(result["removals"], 1);
    assert_eq!(
        result["affected_files"][0]["changed_ranges"][0]["start_line"],
        2
    );
    assert_eq!(
        fs::read_to_string(root.path().join("a")).map_err(io_error)?,
        "a\r\nx\r\nc\r\n"
    );
    Ok(())
}
#[test]
fn copy_dependency_hardlink_gain_after_first_write_rolls_back() -> Result<(), ReCtmError> {
    let (root, _private, w) = setup()?;
    fs::write(root.path().join("a"), "one").map_err(io_error)?;
    let (p, _) = prepare(
        &w,
        &args(json!({"changes":[
            {"action":"copy","path":"a","revision":revision("one"),"destination":"b"},
            {"action":"create","path":"c","content":"new"}
        ]}))?,
    )?;
    let result = w.commit_prepared_patch_with_hook(
        p,
        || Ok(()),
        |i| {
            if i == 1 {
                fs::hard_link(root.path().join("a"), root.path().join("hard")).map_err(io_error)?;
            }
            Ok(())
        },
    );
    assert!(result.is_err());
    assert!(!root.path().join("b").exists());
    assert!(!root.path().join("c").exists());
    Ok(())
}
#[test]
fn production_patch_repeat_move_and_interaction_contract() -> Result<(), ReCtmError> {
    let (root, _private, w) = setup()?;
    fs::write(root.path().join("a"), "context\nnew\n").map_err(io_error)?;
    let inode = fs::metadata(root.path().join("a")).map_err(io_error)?.ino();
    let invocation = PatchInvocation::parse(&args(
        json!({"patch":"*** Begin Patch\n*** Update File: a\n@@\n context\n-old\n+new\n*** End Patch\n"}),
    )?)?;
    let prepared = w.prepare_patch(&invocation)?;
    let result = w.commit_prepared_patch_with_authorization(prepared, || Ok(()))?;
    assert_eq!(result["already_applied"], true);
    assert_eq!(
        fs::metadata(root.path().join("a")).map_err(io_error)?.ino(),
        inode
    );
    for destination in ["a", "./a"] {
        let inv = PatchInvocation::parse(&args(
            json!({"patch":format!("*** Begin Patch\n*** Update File: a\n*** Move to: {destination}\n*** End Patch\n")}),
        )?)?;
        assert!(w.prepare_patch(&inv).is_err());
    }
    let inv = PatchInvocation::parse(&args(
        json!({"patch":"*** Begin Patch\n*** Update File: a\n*** Move to: b\n*** Update File: b\n@@\n context\n-new\n+changed\n*** End Patch\n"}),
    )?)?;
    assert!(w.prepare_patch(&inv).is_err());
    let inv = PatchInvocation::parse(&args(
        json!({"patch":"*** Begin Patch\n*** Update File: a\n*** Move to: b\n*** End Patch\n"}),
    )?)?;
    let result = w.commit_prepared_patch_with_authorization(w.prepare_patch(&inv)?, || Ok(()))?;
    assert_eq!(result["already_applied"], false);
    assert!(
        result["affected_files"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|v| v["operation"] == "delete" && v["path"] == "a")
    );
    assert_eq!(result["affected_files"][1]["old_path"], "a");
    Ok(())
}
