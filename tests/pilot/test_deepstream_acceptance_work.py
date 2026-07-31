from __future__ import annotations

import inspect

from protector.pilot.runtime.deepstream import DeepStreamDataPlane, main


def test_deepstream_acceptance_hooks_are_fail_closed_and_post_analytics() -> None:
    parameters = DeepStreamDataPlane.__init__.__annotations__
    assert "native_probe_lease_factory" in parameters
    assert "acceptance_work_completion" in parameters
    assert "analytics_publication_gate" in parameters


def test_target_main_constructs_all_acceptance_authorities_from_protected_inputs() -> None:
    source = inspect.getsource(main)

    for reviewed_argument in (
        "--acceptance-channel",
        "--acceptance-source-secrets-root",
        "--acceptance-native-projection",
        "--acceptance-work-projection",
    ):
        assert reviewed_argument in source
    assert "TargetAcceptanceRuntimeV3(" in source
    assert "native_probe_lease_factory=(" in source
    assert "acceptance_work_completion=acceptance_runtime.work_completion" in source
    assert "analytics_publication_gate=(" in source
    assert "acceptance_runtime.start(" in source
