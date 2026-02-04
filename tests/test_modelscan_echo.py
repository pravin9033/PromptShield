from pathlib import Path

from promptshield.modelscan import EchoAdapter, run_model_scan
from promptshield.redteam.packs import AttackCase, AttackPack


def test_modelscan_with_echo_adapter():
    pack = AttackPack(
        name="test-pack",
        version="1.0",
        description="",
        attacks=[AttackCase(attack_id="t1", prompt="Hello", category="BENIGN")],
        source_path=Path(__file__),
    )
    result = run_model_scan(pack, EchoAdapter())
    assert result.outcomes[0].output == "Hello"
