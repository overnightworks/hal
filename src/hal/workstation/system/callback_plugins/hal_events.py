"""The `default` screen output of Ansible plus one marker-prefixed JSON line per started task, per changed task (a failed task that changed included), per failed result and one for the final counts.

`hal setup` reads these lines to judge the root run, to show the task running now, to name the tasks a check found to change and to show a failed task's message.
The play's own text stays as `default` prints it; `hal setup` shows it only with `-v`.
"""

from __future__ import annotations

import json
import sys

from ansible.plugins.callback.default import CallbackModule as DefaultCallbackModule

DOCUMENTATION = """
    name: hal_events
    type: stdout
    short_description: default Ansible screen output plus hal's event lines
    description:
        - The default output callback, followed by one JSON line per started task (handlers included), per changed task (a failed task that changed included), per failed or unreachable result and one for the final counts.
    extends_documentation_fragment:
      - default_callback
      - result_format_callback
    requirements:
      - set as stdout in configuration
"""

# hal.workstation.system_step.EVENT_MARK states the same mark: this file runs in Ansible's interpreter and cannot import hal.
EVENT_MARK = "\x1ehal_events "


class CallbackModule(DefaultCallbackModule):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "stdout"
    CALLBACK_NAME = "hal_events"

    def v2_playbook_on_task_start(self, task, is_conditional):
        super().v2_playbook_on_task_start(task, is_conditional)
        self._write_event({"event": "task", "task": task.get_name().strip()})

    def v2_playbook_on_handler_task_start(self, task):
        super().v2_playbook_on_handler_task_start(task)
        self._write_event({"event": "task", "task": task.get_name().strip()})

    def v2_runner_on_ok(self, result):
        super().v2_runner_on_ok(result)
        if result.is_changed():
            self._write_event({"event": "changed", "task": result.task_name})

    def v2_runner_on_failed(self, result, ignore_errors=False):
        super().v2_runner_on_failed(result, ignore_errors)
        # Ansible's count leaves out a failed task, yet a loop can fail after its first item wrote; an ignored failure is counted.
        if result.is_changed():
            self._write_event({"event": "changed", "task": result.task_name})
        if not ignore_errors:
            self._write_result("failed", result)

    def v2_runner_on_unreachable(self, result):
        super().v2_runner_on_unreachable(result)
        self._write_result("unreachable", result)

    def v2_playbook_on_stats(self, stats):
        super().v2_playbook_on_stats(stats)
        summaries = [stats.summarize(host) for host in sorted(stats.processed)]
        self._write_event(
            {
                "event": "counts",
                "changed": sum(summary["changed"] for summary in summaries),
                "failed": sum(summary["failures"] for summary in summaries),
                "unreachable": sum(summary["unreachable"] for summary in summaries),
            }
        )

    def _write_result(self, status, result):
        self._write_event({"event": "result", "status": status, "msg": str(result.result.get("msg", ""))})

    # Display.display never flushes, and the play's stderr shares this pipe: flushing around the line keeps it whole.
    def _write_event(self, event):
        sys.stdout.flush()
        self._display.display(EVENT_MARK + json.dumps(event), screen_only=True)
        sys.stdout.flush()
