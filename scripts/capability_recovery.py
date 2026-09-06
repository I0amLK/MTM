"""Bounded test/client helper; never grants authority or logs capability contents.

A callback is bound to ONE endpoint and OAuth principal. The caller keeps one
cursor per task/run, not a single global capability for all runs or branches.
The web model is not automatically made to use this helper by a server update.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any, Callable

Task = dict[str, Any]


class RecoveryStop(RuntimeError):
    """Fixed safe messages only; never include requests, tokens or proof text."""


def _submission(task: Task) -> Task:
    value = task.get("submission")
    return value if isinstance(value, dict) else {}


def _code(task: Task) -> str:
    value = _submission(task).get("error", task.get("error", {}))
    return str(value.get("code", "")) if isinstance(value, dict) else ""


def _check_arguments(task: Task, arguments: Task) -> None:
    token = task.get("capability")
    if not isinstance(token, str) or not token:
        raise RecoveryStop("Current task contains no usable capability.")
    if arguments.get("run_id") != task.get("run_id") or arguments.get("capability") != token:
        raise RecoveryStop("Submission must use the exact current task/run envelope.")


def adopt_refresh(current: Task, response: Task) -> Task:
    """Return a new cursor for THIS run only; never mutate a different cursor."""
    sub = _submission(response)
    if not (
        _code(response) == "CAPABILITY_INVALID"
        and sub.get("capability_refreshed") is True
        and sub.get("recoverable") is True
        and sub.get("retryable") is True
        and sub.get("writes_retained") is False
        and type(response.get("writes_applied")) is int
        and response["writes_applied"] == 0
    ):
        raise RecoveryStop("Response does not permit a zero-write capability retry.")
    if not current.get("run_id") or response.get("run_id") != current["run_id"]:
        raise RecoveryStop("Refresh response belongs to a different run.")
    token = response.get("capability")
    if not isinstance(token, str) or not token or token == current.get("capability"):
        raise RecoveryStop("Refresh response contains no new capability.")
    if response.get("state") != current.get("state"):
        raise RecoveryStop("Task state changed; inspect and replan instead of replaying.")
    old_task, new_task = current.get("task"), response.get("task")
    if not isinstance(old_task, dict) or not isinstance(new_task, dict):
        raise RecoveryStop("Refresh response is missing the current task contract.")
    for key in ("role", "domain_id", "epoch"):
        if current.get(key) != response.get(key):
            raise RecoveryStop("Task authority context changed; inspect before resubmitting.")
    for key in ("commit_action", "write_contract", "commit_payload_schema"):
        if old_task.get(key) != new_task.get(key):
            raise RecoveryStop("Task contract changed; inspect before resubmitting.")
    return deepcopy(response)


def submit_with_one_refresh(
    current: Task,
    prepare: Callable[[Task], Task],
    call: Callable[[Task], Task],
) -> Task:
    """At most TWO requests. Rebuild from the refreshed task; never replay blindly."""
    cursor = deepcopy(current)
    arguments = prepare(deepcopy(cursor))
    _check_arguments(cursor, arguments)
    response = call(arguments)
    if _submission(response).get("capability_refreshed") is not True:
        return response
    cursor = adopt_refresh(cursor, response)
    arguments = prepare(deepcopy(cursor))
    _check_arguments(cursor, arguments)
    response = call(arguments)
    if _code(response) == "CAPABILITY_INVALID" or _submission(response).get("capability_refreshed") is True:
        raise RecoveryStop("Second capability rejection; stop retries and inspect the current task.")
    return response
