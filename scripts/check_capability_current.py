#!/usr/bin/env python3
"""Permanent current-binary capability gate, independent of milestone selectors.

Uses disposable loopback state only. This does NOT test the web-model, Quick Tunnel,
Bubblewrap, or target installation. Frozen historical harnesses are not rewritten.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


class GateFailure(RuntimeError):
    pass


def require(value, label):
    if not value:
        raise GateFailure(label)


def digest(path):
    h=hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda:handle.read(1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()


def source_digest():
    h=hashlib.sha256()
    paths=sorted(set(ROOT.glob("crates/**/*.rs")) | set(ROOT.glob("crates/**/Cargo.toml")) |
                 {ROOT/"Cargo.toml",ROOT/"Cargo.lock"})
    for path in paths:
        h.update(str(path.relative_to(ROOT)).encode()); h.update(b"\0")
        h.update(bytes.fromhex(digest(path)))
    return h.hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    choice=parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--build",action="store_true")
    choice.add_argument("--binary",type=Path)
    parser.add_argument("--samples",type=int,default=500)
    parser.add_argument("--report",type=Path,default=ROOT/"records/validation/capability-current.json")
    args=parser.parse_args()
    if not 1 <= args.samples <= 2000:
        parser.error("--samples must be between 1 and 2000")
    report={"schema_version":"1.0.0","introduced_in":"MTM-015",
            "kind":"current_binary_loopback_capability_regression","ok":False,
            "samples_requested":args.samples,"normal_roundtrips":0,"normal_invalid":0,
            "raw_capability_recorded":False,"raw_oauth_token_recorded":False,
            "web_client_tested":False,"production_state_modified":False,"checks":{}}
    stage="source_identity"
    try:
        report["source_sha256"]=source_digest()
        if args.build:
            stage="build"
            from run_checks import resolve_tool_environment
            environment,cargo,_=resolve_tool_environment()
            require(cargo is not None,"rust_toolchain_unavailable")
            target=ROOT/"target"
            result=subprocess.run([cargo,"build","--locked","-p","mtm-cli","--bin","mtm",
                                   "--target-dir",str(target)],cwd=ROOT,env=environment,
                                   stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                                   timeout=600,check=False)
            require(result.returncode==0,"current_source_build_failed")
            binary=target/"debug/mtm"
        else:
            binary=args.binary.resolve()
        require(binary.is_file(),"binary_missing")
        report["binary_sha256"]=digest(binary)
        import run_mtm013_runtime_hardening as frozen
        with tempfile.TemporaryDirectory(prefix="mtm-current-capability-") as temp:
            root=Path(temp)
            frozen.BINARY=binary
            frozen.REPORT=root/"frozen-regression.json"
            stage="frozen_mutation_corpus"
            # Exceptions in historical helpers may contain tokens; never print them.
            with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
                result=frozen.main()
            historical=json.loads(frozen.REPORT.read_text())
            require(result==0 and historical.get("ok") is True,"frozen_capability_corpus_failed")
            report["checks"].update(historical["checks"])
            report["frozen_harness_sha256"]=digest(Path(frozen.__file__))
            stage="normal_roundtrips"
            process,port,base=frozen.launch(root/"roundtrip")
            try:
                owner=frozen.oauth_token(port,base,"Current capability gate")
                for index in range(args.samples):
                    task=frozen.start_run(port,owner,f"mtm-current-{index}")
                    # The exact object bytes are copied by the program, not retyped by a model.
                    response=frozen.tool_call(port,owner,"rethlas_step",
                                              frozen.task_submission(task,task["capability"]))
                    value=frozen.structured(response)
                    sub=value.get("submission",{})
                    code=(sub.get("error",{}).get("code") or value.get("error",{}).get("code"))
                    if code=="CAPABILITY_INVALID" or sub.get("capability_refreshed") is True:
                        report["normal_invalid"]+=1
                        raise GateFailure("unexpected_invalid_on_verbatim_roundtrip")
                    require(not frozen.is_error(response),"normal_submission_failed")
                    require(value.get("ok") is True and sub.get("ok") is not False,
                            "normal_submission_unsuccessful")
                    require(value.get("state") != task["state"],"normal_submission_did_not_advance")
                    expected=len(task["task"]["minimal_submission"].get("writes",[]))
                    require(type(value.get("writes_applied")) is int and value["writes_applied"]==expected,
                            "normal_write_count_mismatch")
                    report["normal_roundtrips"]+=1
                    cancelled=frozen.tool_call(port,owner,"rethlas_control",{
                        "action":"cancel","run_id":task["run_id"],"reason":"disposable_regression_complete"})
                    require(not frozen.is_error(cancelled),"disposable_run_cancel_failed")
            finally:
                exit_code=frozen.close(process)
            require(exit_code==0,"server_shutdown_failed")
            require(report["source_sha256"]==source_digest(),"source_changed_during_gate")
            report["checks"]["verbatim_roundtrips_without_refresh"]=True
            report["checks"]["bounded_server_shutdown"]=True
            report["ok"]=True
    except Exception as error:
        report["failed_stage"]=stage
        report["failure"]=str(error) if isinstance(error,GateFailure) else type(error).__name__
    # Reports are regenerable summaries, never historical accepted receipts.
    report["harness_sha256"]=digest(Path(__file__))
    report_path=args.report.resolve()
    report_path.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w",dir=report_path.parent,encoding="utf-8",delete=False) as handle:
        temporary=Path(handle.name)
        json.dump(report,handle,sort_keys=True,indent=2); handle.write("\n")
    try:
        os.replace(temporary,report_path)
    finally:
        temporary.unlink(missing_ok=True)
    print(json.dumps(report,sort_keys=True))
    return 0 if report["ok"] else 1


if __name__=="__main__":
    raise SystemExit(main())
