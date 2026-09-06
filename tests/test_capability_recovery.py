from __future__ import annotations

import sys
import unittest
from copy import deepcopy
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from capability_recovery import RecoveryStop, adopt_refresh, submit_with_one_refresh


def task(run="A", token="original"):
    return {"run_id":run,"state":"assess","capability":token,"task":{
        "commit_action":"finish_assessment","write_contract":{},"commit_payload_schema":{}
    }}


def refresh(run="A", token="fresh"):
    value=task(run,token)
    value.update(writes_applied=0,submission={"ok":False,"capability_refreshed":True,
        "recoverable":True,"retryable":True,"writes_retained":False,
        "error":{"code":"CAPABILITY_INVALID"}})
    return value


def prepare(value):
    return {"run_id":value["run_id"],"capability":value["capability"],"action":"finish_assessment"}


class RecoveryTests(unittest.TestCase):
    def test_normal_path_is_one_call(self):
        calls=[]
        result=submit_with_one_refresh(task(),prepare,lambda args: calls.append(args) or {"ok":True})
        self.assertTrue(result["ok"])
        self.assertEqual(len(calls),1)

    def test_uses_new_token_once_without_mutating_other_run(self):
        a,b=task(),task("B","B-token")
        saved=deepcopy((a,b)); calls=[]
        responses=iter([refresh(),{"ok":True,"state":"assemble"}])
        result=submit_with_one_refresh(a,prepare,lambda args: calls.append(args) or next(responses))
        self.assertEqual([x["capability"] for x in calls],["original","fresh"])
        self.assertEqual(result["state"],"assemble")
        self.assertEqual((a,b),saved)

    def test_second_refresh_stops_at_two_requests(self):
        calls=[]; responses=iter([refresh(),refresh(token="fresh-2")])
        with self.assertRaises(RecoveryStop):
            submit_with_one_refresh(task(),prepare,lambda args: calls.append(args) or next(responses))
        self.assertEqual(len(calls),2)

    def test_cross_run_is_rejected(self):
        with self.assertRaises(RecoveryStop): adopt_refresh(task(),refresh("B"))

    def test_state_change_is_not_replayed(self):
        value=refresh(); value["state"]="assemble"
        with self.assertRaises(RecoveryStop): adopt_refresh(task(),value)

    def test_changed_contract_is_not_replayed(self):
        value=refresh(); value["task"]["write_contract"]={"new":"contract"}
        with self.assertRaises(RecoveryStop): adopt_refresh(task(),value)

    def test_retained_or_unknown_writes_are_not_replayed(self):
        for value in (1,None,False,-1):
            changed=refresh(); changed["writes_applied"]=value
            with self.subTest(value=value),self.assertRaises(RecoveryStop): adopt_refresh(task(),changed)
        changed=refresh(); changed["submission"]["writes_retained"]=True
        with self.assertRaises(RecoveryStop): adopt_refresh(task(),changed)

    def test_revoked_is_never_refreshed(self):
        value=refresh(); value["submission"]["error"]["code"]="CAPABILITY_REVOKED"
        with self.assertRaises(RecoveryStop): adopt_refresh(task(),value)

    def test_stale_preparer_is_rejected_before_first_call(self):
        calls=[]
        with self.assertRaises(RecoveryStop):
            submit_with_one_refresh(task(),lambda value:{"run_id":"A","capability":"wrong"},
                                    lambda args:calls.append(args) or {})
        self.assertEqual(calls,[])

    def test_empty_or_unchanged_token_is_rejected_without_leak(self):
        for token in (None,"","original"):
            with self.subTest(token=token),self.assertRaises(RecoveryStop) as raised:
                adopt_refresh(task(),refresh(token=token))
            self.assertNotIn("original",str(raised.exception))

    def test_role_domain_and_epoch_changes_stop_retry(self):
        for key in ("role","domain_id","epoch"):
            value=refresh(); value[key]="different"
            with self.subTest(key=key),self.assertRaises(RecoveryStop): adopt_refresh(task(),value)


if __name__=="__main__": unittest.main()
