"""Command-line interface. Secrets are prompted or read from an environment variable."""

from __future__ import annotations

import json
import os
from getpass import getpass
from pathlib import Path
from typing import Any

import typer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from skillcred.badge import create_credential
from skillcred.i18n import translate
from skillcred.keys import (
    generate_keypair,
    identity_from_private_key,
    private_key_from_base64,
)
from skillcred.statuslist import StatusListManager
from skillcred.storage import (
    WalletError,
    _atomic_write,
    export_wallet,
    load_wallet,
    save_wallet,
    wallet_from_key,
)
from skillcred.verify import verify_credential

app = typer.Typer(no_args_is_help=True, help="Issue and verify portable skill credentials.")


def _password() -> str:
    value = os.environ.get("SKILLCRED_PASSWORD")
    return value if value else getpass("Wallet passphrase: ")


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise typer.BadParameter(f"Cannot read JSON document: {path}") from exc
    if not isinstance(value, dict):
        raise typer.BadParameter("Expected a JSON object")
    return value


def _write_json(path: Path, value: Any) -> None:
    """Write artifacts atomically with owner-only permissions by default.

    Credentials may contain personal data, so public readability must be an
    explicit deployment decision rather than the CLI default.
    """
    contents = (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    _atomic_write(path.expanduser().resolve(), contents, mode=0o600)


def _load_private_key(wallet_path: Path) -> tuple[dict[str, Any], Ed25519PrivateKey]:
    wallet = load_wallet(wallet_path, _password())
    key = private_key_from_base64(str(wallet["private_key"]))
    return wallet, key


@app.command()
def init(
    wallet: Path = typer.Option(
        Path("skillcred.wallet"), "--wallet", help="Encrypted wallet output path"
    ),
    issuer_name: str = typer.Option(
        "SkillCred Local Issuer", "--issuer-name", help="Public issuer display name"
    ),
) -> None:
    """Create an Ed25519 issuer key and an encrypted local wallet."""
    if wallet.exists():
        raise typer.BadParameter(translate("wallet_exists", path=wallet))
    passphrase = _password()
    if len(passphrase) < 12:
        raise typer.BadParameter(translate("passphrase_short"))
    private_key = generate_keypair()
    data = wallet_from_key(private_key, issuer_name)
    save_wallet(wallet, data, passphrase)
    identity = identity_from_private_key(private_key)
    typer.echo(
        json.dumps(
            {
                "message": translate("wallet_created"),
                "wallet": str(wallet.resolve()),
                "issuer_id": identity.did,
            },
            indent=2,
            ensure_ascii=False,
        )
    )


@app.command()
def issue(
    achievement: str = typer.Option(..., "--achievement", help="Skill or achievement name"),
    description: str = typer.Option(..., "--description", help="Criteria or summary"),
    wallet: Path = typer.Option(
        Path("skillcred.wallet"), "--wallet", help="Encrypted issuer wallet"
    ),
    subject_id: str | None = typer.Option(
        None, "--subject-id", help="Optional learner identifier; omitted by default"
    ),
    out: Path = typer.Option(Path("credential.json"), "--out", help="Credential JSON output path"),
    with_status: bool = typer.Option(
        False, "--with-status", help="Allocate a revocation status entry"
    ),
    data_dir: Path = typer.Option(
        Path("skillcred-data"), "--data-dir", help="Local status state directory"
    ),
    status_list_url: str = typer.Option(
        "https://issuer.example/status-list",
        "--status-list-url",
        help="Status-list credential URL",
    ),
) -> None:
    """Issue a signed credential. A real-world learner identifier is optional; an unrelated per-credential URN is generated when omitted."""
    try:
        wallet_data, key = _load_private_key(wallet)
        status_entry = None
        if with_status:
            manager = StatusListManager(
                data_dir, key, str(wallet_data["issuer_name"]), status_list_url
            )
            status_entry = manager.allocate()
        credential = create_credential(
            key,
            issuer_name=str(wallet_data["issuer_name"]),
            achievement_name=achievement,
            achievement_description=description,
            subject_id=subject_id,
            credential_status=status_entry,
        )
        _write_json(out, credential)
    except (WalletError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(translate("issued", path=out.resolve(), id=credential["id"]))


@app.command()
def verify(
    credential: Path = typer.Argument(..., exists=True, readable=True),
    status_list: Path | None = typer.Option(
        None, "--status-list", help="Optional signed status-list credential"
    ),
) -> None:
    """Verify credential signature offline; check revocation if a list is supplied."""
    document = _read_json(credential)
    status_doc = _read_json(status_list) if status_list else None
    result = verify_credential(document, status_list_credential=status_doc)
    typer.echo(json.dumps(result, indent=2, ensure_ascii=False))
    if not result["valid"]:
        raise typer.Exit(code=1)


@app.command()
def export(
    source: Path = typer.Option(
        Path("skillcred.wallet"), "--wallet", help="Encrypted wallet source"
    ),
    out: Path = typer.Option(..., "--out", help="Destination for encrypted wallet copy"),
) -> None:
    """Export a byte-for-byte copy of the encrypted wallet (not the plaintext key)."""
    try:
        export_wallet(source, out)
    except WalletError as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(translate("wallet_copied", path=out.resolve()))


@app.command()
def info(
    wallet: Path = typer.Option(Path("skillcred.wallet"), "--wallet", help="Encrypted wallet"),
) -> None:
    """Display public issuer metadata only; never display private-key bytes."""
    try:
        wallet_data = load_wallet(wallet, _password())
    except WalletError as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(
        json.dumps(
            {
                "wallet": str(wallet.resolve()),
                "issuer_name": wallet_data.get("issuer_name"),
                "issuer_id": wallet_data.get("issuer_id"),
                "verification_method": wallet_data.get("verification_method"),
                "key_type": "Ed25519",
                "wallet_encrypted": True,
            },
            indent=2,
            ensure_ascii=False,
        )
    )


@app.command("status-list")
def status_list(
    wallet: Path = typer.Option(
        Path("skillcred.wallet"), "--wallet", help="Encrypted issuer wallet"
    ),
    data_dir: Path = typer.Option(
        Path("skillcred-data"), "--data-dir", help="Local issuer status state"
    ),
    url: str = typer.Option(
        "https://issuer.example/status-list", "--url", help="Public status list URL"
    ),
    out: Path = typer.Option(Path("status-list.json"), "--out", help="Signed status list output"),
) -> None:
    """Generate a signed snapshot of this issuer's local revocation list."""
    try:
        wallet_data, key = _load_private_key(wallet)
        manager = StatusListManager(data_dir, key, str(wallet_data["issuer_name"]), url)
        _write_json(out, manager.create_credential())
    except (WalletError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(translate("status_written", path=out.resolve()))


@app.command()
def revoke(
    index: int = typer.Argument(..., min=0),
    wallet: Path = typer.Option(
        Path("skillcred.wallet"), "--wallet", help="Encrypted issuer wallet"
    ),
    data_dir: Path = typer.Option(
        Path("skillcred-data"), "--data-dir", help="Local issuer status state"
    ),
    url: str = typer.Option(
        "https://issuer.example/status-list", "--url", help="Public status list URL"
    ),
) -> None:
    """Revoke an allocated status index; publish a fresh list with `status-list`."""
    try:
        wallet_data, key = _load_private_key(wallet)
        manager = StatusListManager(data_dir, key, str(wallet_data["issuer_name"]), url)
        manager.revoke(index)
    except (WalletError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(translate("revoked", index=index))


if __name__ == "__main__":
    app()
