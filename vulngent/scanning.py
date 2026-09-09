"""Orchestrates running external scanners (SAST, SCA, secrets) against a repository
and normalizing their output into vulngent's import format."""

from __future__ import annotations

import json
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from rich.console import Console

from vulngent.ingestion import normalizers
from vulngent.ingestion.importer import import_file
from vulngent.integrations.github_client import parse_repo_full_name

console = Console()


class ScanError(Exception):
    pass


@contextmanager
def _git_clone(repo_url: str) -> Iterator[Path]:
    """Clone a repo into a temporary directory that is cleaned up on exit."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = Path(tmpdir)
        console.print(f":arrow_down: Cloning {repo_url} into {repo_path}...")
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, "."],
                cwd=repo_path,
                check=True,
                capture_output=True,
                text=True,
            )
            yield repo_path
        except FileNotFoundError:
            raise ScanError("git is not installed or not in PATH. Please install it to use the scan command.")
        except subprocess.CalledProcessError as exc:
            raise ScanError(f"Failed to clone {repo_url}:\n{exc.stderr}")


def run_semgrep_scan(repo_path: Path, output_file: Path) -> None:
    """Run Semgrep for SAST."""
    console.print(":mag: Running SAST scan with Semgrep...")
    try:
        subprocess.run(
            ["semgrep", "scan", "--config", "auto", "--json", "-o", str(output_file)],
            cwd=repo_path,
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        raise ScanError("semgrep is not installed or not in PATH. See https://semgrep.dev/docs/getting-started/")
    except subprocess.CalledProcessError as exc:
        if exc.returncode != 1:
            raise ScanError(f"Semgrep failed:\n{exc.stderr}")


def run_trufflehog_scan(repo_path: Path, output_file: Path) -> None:
    """Run TruffleHog for secret scanning."""
    console.print(":key: Running secret scan with TruffleHog...")
    try:
        with open(output_file, "w") as f:
            subprocess.run(
                ["trufflehog", "filesystem", ".", "--json"],
                cwd=repo_path,
                check=True,
                stdout=f,
                stderr=subprocess.PIPE,
                text=True,
            )
    except FileNotFoundError:
        raise ScanError("trufflehog is not installed or not in PATH. See https://github.com/trufflesecurity/trufflehog")
    except subprocess.CalledProcessError as exc:
        raise ScanError(f"TruffleHog failed:\n{exc.stderr}")

def run_trivy_sca_scan(repo_path: Path, output_file: Path) -> None:
    """Run Trivy for SCA (dependency) scanning."""
    console.print(":package: Running SCA scan with Trivy...")
    try:
        subprocess.run(
            [
                "trivy",
                "fs",
                "--scanners",
                "vuln",
                "--format",
                "json",
                "--output",
                str(output_file),
                ".",
            ],
            cwd=repo_path,
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        raise ScanError("trivy is not installed or not in PATH. See https://aquasecurity.github.io/trivy/v0.56/getting-started/installation/")
    except subprocess.CalledProcessError as exc:
        raise ScanError(f"Trivy failed:\n{exc.stderr}")


def run_scan_pipeline(repo_url: str, scanners_to_run: str) -> None:
    """Main entrypoint for the scan command."""
    try:
        repo_full_name = parse_repo_full_name(repo_url)
    except ValueError as exc:
        raise ScanError(str(exc))

    with _git_clone(repo_url) as repo_path:
        console.print(f"[green]Successfully cloned {repo_full_name}.[/green]")
        output_dir = Path(tempfile.mkdtemp(prefix="vulngent-scan-"))
        console.print(f"Saving scan results to {output_dir}")

        scanners = scanners_to_run.lower().split(",")

        if "all" in scanners or "sast" in scanners:
            run_semgrep_scan(repo_path, output_dir / "semgrep.json")
        if "all" in scanners or "secrets" in scanners:
            run_trufflehog_scan(repo_path, output_dir / "trufflehog.jsonl")
        if "all" in scanners or "sca" in scanners:
            run_trivy_sca_scan(repo_path, output_dir / "trivy_fs.json")

        try:
            console.print("\n:inbox_tray: Normalizing and importing findings...")
            all_records = []
            if (output_dir / "semgrep.json").exists():
                report = json.loads((output_dir / "semgrep.json").read_text())
                all_records.extend(normalizers.normalize_semgrep(report, asset_name=repo_full_name, repo_full_name=repo_full_name))
            if (output_dir / "trufflehog.jsonl").exists():
                all_records.extend(normalizers.normalize_trufflehog(output_dir / "trufflehog.jsonl", asset_name=repo_full_name, repo_full_name=repo_full_name))
            if (output_dir / "trivy_fs.json").exists():
                report = json.loads((output_dir / "trivy_fs.json").read_text())
                all_records.extend(normalizers.normalize_trivy_fs(report, asset_name=repo_full_name, repo_full_name=repo_full_name))

            console.print(f"Normalizing {len(all_records)} records...")
            if not all_records:
                console.print("[green]No findings to import.[/green]")
                return

            import_path = output_dir / "vulngent-import.json"
            with open(import_path, "w") as f:
                json.dump([r.model_dump() for r in all_records], f, indent=2)

            from vulngent.db.session import get_session, init_db

            init_db()
            with get_session() as session:
                result = import_file(session, import_path)

            console.print(f"[green]Imported {result.created} new findings.[/green]")
            if result.skipped_duplicate:
                console.print(f"[yellow]Skipped {len(result.skipped_duplicate)} duplicates.[/yellow]")
        except Exception:
            console.print_exception()
