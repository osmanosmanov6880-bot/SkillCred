"""Offline end-to-end issuance, export, verification and revocation demonstration."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from skillcred.badge import create_credential
from skillcred.keys import generate_keypair
from skillcred.statuslist import StatusListManager
from skillcred.storage import _atomic_write
from skillcred.verify import verify_credential


def write_json(path: Path, value: object) -> None:
    contents = (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    _atomic_write(path.resolve(), contents, mode=0o600)


def main() -> int:
    out = Path("demo-output").resolve()
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    key = generate_keypair()
    manager = StatusListManager(
        out / "issuer-state",
        key,
        "SkillCred Pilot Issuer",
        "https://issuer.example/status-list",
    )

    status_entry = manager.allocate()
    credential = create_credential(
        key,
        issuer_name="SkillCred Pilot Issuer",
        achievement_name="Practical Safety Skills",
        achievement_description="Completed an assessment of the declared practical skills.",
        credential_status=status_entry,
    )
    issued_path = out / "issued-credential.json"
    write_json(issued_path, credential)

    exported_path = out / "recipient-export" / "credential.json"
    exported_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(issued_path, exported_path)
    status_path = out / "status-list-active.json"
    active_status = manager.create_credential()
    write_json(status_path, active_status)
    exported_credential = json.loads(exported_path.read_text(encoding="utf-8"))
    active_result = verify_credential(
        exported_credential, status_list_credential=active_status
    )

    manager.revoke(int(status_entry["statusListIndex"]))
    revoked_status = manager.create_credential()
    revoked_path = out / "status-list-revoked.json"
    write_json(revoked_path, revoked_status)
    revoked_result = verify_credential(
        exported_credential, status_list_credential=revoked_status
    )

    print(
        json.dumps(
            {
                "issued": str(issued_path),
                "exported": str(exported_path),
                "active_check": active_result,
                "after_revocation": revoked_result,
            },
            indent=2,
            ensure_ascii=False,
        )
    )
    if (
        not active_result["valid"]
        or revoked_result["status"] != "revoked"
        or revoked_result["valid"]
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
