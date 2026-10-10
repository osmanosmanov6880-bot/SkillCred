from __future__ import annotations

import json
import shutil

from skillcred.badge import create_credential
from skillcred.keys import generate_keypair
from skillcred.statuslist import StatusListManager
from skillcred.verify import verify_credential


def test_issue_export_verify_revoke_end_to_end(tmp_path) -> None:
    issuer_key = generate_keypair()
    manager = StatusListManager(
        tmp_path / "issuer-state", issuer_key, "E2E Issuer", "https://issuer.example/status-list"
    )
    status_entry = manager.allocate()
    credential = create_credential(
        issuer_key,
        issuer_name="E2E Issuer",
        achievement_name="E2E Achievement",
        achievement_description="A credential used by the end-to-end test.",
        credential_status=status_entry,
    )
    issued = tmp_path / "issued.json"
    exported = tmp_path / "recipient" / "credential.json"
    issued.write_text(json.dumps(credential), encoding="utf-8")
    exported.parent.mkdir()
    shutil.copyfile(issued, exported)

    active = verify_credential(
        json.loads(exported.read_text(encoding="utf-8")),
        status_list_credential=manager.create_credential(),
    )
    assert active["valid"] is True
    manager.revoke(int(status_entry["statusListIndex"]))
    revoked = verify_credential(
        json.loads(exported.read_text(encoding="utf-8")),
        status_list_credential=manager.create_credential(),
    )
    assert revoked["signature_valid"] is True
    assert revoked["status"] == "revoked"
    assert revoked["valid"] is False
