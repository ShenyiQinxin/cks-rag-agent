"""
CLI entrypoint for the CKS Architect Design Agent.

Single-shot:
    python -m src "Generate a diagram for Kubernetes RBAC"
    python -m src "Generate a threat model for etcd access" --save
    python -m src --manifest data/manifests/insecure-pod.yaml --save

Interactive session (multi-turn):
    python -m src
"""
import sys
import re
import uuid
from pathlib import Path
from dotenv import load_dotenv
load_dotenv()

from src.agent import stream_agent

OUTPUT_DIR = Path(__file__).parent.parent / "output"


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")[:50]


def _extension(result: str) -> str:
    if "sequenceDiagram" in result or "graph TD" in result or "graph LR" in result:
        return ".mmd"
    return ".md"


def _save(label: str, result: str) -> Path:
    OUTPUT_DIR.mkdir(exist_ok=True)
    path = OUTPUT_DIR / (_slug(label) + _extension(result))
    path.write_text(result)
    return path


def _get_manifest_flag(argv: list[str]) -> str | None:
    for i, arg in enumerate(argv):
        if arg == "--manifest" and i + 1 < len(argv):
            return argv[i + 1]
    return None


def _run_once(query: str, label: str, save: bool, thread_id: str) -> None:
    print(label)
    print("-" * 60)
    result = stream_agent(query, thread_id=thread_id)
    if save:
        path = _save(label, result)
        print(f"Saved → {path}")


def _repl(thread_id: str) -> None:
    print(f"CKS Agent  |  session: {thread_id[:8]}  |  type 'exit' to quit")
    print("=" * 60)
    while True:
        try:
            user_input = input("\n> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nSession ended.")
            break

        if not user_input:
            continue
        if user_input.lower() in ("exit", "quit"):
            print("Session ended.")
            break

        # Parse flags first so they don't bleed into paths or queries
        tokens = user_input.split()
        save = "--save" in tokens
        clean_input = " ".join(t for t in tokens if t != "--save").strip()

        # Support --manifest inside the REPL
        if clean_input.startswith("--manifest "):
            manifest_path = Path(clean_input.split(" ", 1)[1].strip())
            if not manifest_path.exists():
                print(f"File not found: {manifest_path}")
                continue
            query = f"Analyze this Kubernetes manifest:\n\n{manifest_path.read_text()}"
            label = f"Manifest: {manifest_path.name}"
        else:
            query = clean_input
            label = clean_input

        print()
        result = stream_agent(query, thread_id=thread_id)
        if save:
            path = _save(label, result)
            print(f"Saved → {path}")


def main():
    argv = sys.argv[1:]
    save = "--save" in argv
    manifest_path = _get_manifest_flag(argv)
    args = [a for a in argv if not a.startswith("--") and a not in (manifest_path or [])]
    thread_id = str(uuid.uuid4())

    if manifest_path:
        path = Path(manifest_path)
        if not path.exists():
            print(f"Error: manifest file not found: {manifest_path}")
            sys.exit(1)
        query = f"Analyze this Kubernetes manifest:\n\n{path.read_text()}"
        _run_once(query, f"Manifest: {path.name}", save, thread_id)

    elif args:
        query = " ".join(args)
        _run_once(query, f"Query: {query}", save, thread_id)

    else:
        # No args — start interactive REPL
        _repl(thread_id)


if __name__ == "__main__":
    main()
