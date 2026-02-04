from pathlib import Path

from promptshield.redteam import load_attack_pack


def test_load_attack_pack():
    root = Path(__file__).resolve().parents[1]
    pack = load_attack_pack(str(root / "attacks" / "packs" / "starter.yaml"))
    assert pack.attacks
