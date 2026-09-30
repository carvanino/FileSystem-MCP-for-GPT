#!/usr/bin/env python3
"""Filesystem MCP server using the official MCP Python SDK."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings

DEFAULT_TIMEOUT_SEC = 30
MAX_STDOUT_CHARS = 200_000
MAX_STDERR_CHARS = 200_000
MAX_FILE_SIZE = 1024 * 1024

if len(sys.argv) != 2:
    print("Usage: python3 fileSystemMCP.py <directory_path>")
    sys.exit(1)

ALLOWED_DIRECTORY = Path(sys.argv[1]).expanduser().resolve()

if not ALLOWED_DIRECTORY.exists() or not ALLOWED_DIRECTORY.is_dir():
    print(f"Error: {ALLOWED_DIRECTORY} is not a valid directory")
    sys.exit(1)

mcp = MCPServer("Filesystem MCP")

TRANSPORT_SECURITY = TransportSecuritySettings(
    enable_dns_rebinding_protection=True,
    allowed_hosts=[
        "6d4d-197-211-57-51.ngrok-free.app",
        "6d4d-197-211-57-51.ngrok-free.app:*",
        "127.0.0.1",
        "127.0.0.1:*",
        "localhost",
        "localhost:*",
    ],
    allowed_origins=[],
)


def validate_path(user_path: str) -> Path:
    """Resolve a path and ensure it remains inside the allowed directory."""
    candidate = Path(user_path).expanduser()
    if candidate.is_absolute():
        resolved = candidate.resolve()
    else:
        resolved = (ALLOWED_DIRECTORY / candidate).resolve()

    try:
        resolved.relative_to(ALLOWED_DIRECTORY)
    except ValueError as exc:
        raise PermissionError("Path outside allowed directory") from exc

    return resolved


def restricted_env() -> dict[str, str]:
    """Return an environment with common cloud and SSH credentials removed."""
    env = os.environ.copy()
    blocked_prefixes = (
        "AWS_",
        "GCP_",
        "AZURE_",
        "DOCKER_",
        "KUBECONFIG",
        "SSH_",
    )
    for key in list(env):
        if key.upper().startswith(blocked_prefixes):
            env.pop(key, None)
    return env


@mcp.tool()
def search(query: str) -> dict[str, Any]:
    """Search for files and directories. An empty query lists the workspace root."""
    results: list[dict[str, str]] = []
    normalized = (query or "").lower().strip()

    if not normalized:
        items = sorted(
            ALLOWED_DIRECTORY.iterdir(),
            key=lambda path: (not path.is_dir(), path.name.lower()),
        )
        for item in items:
            rel = item.relative_to(ALLOWED_DIRECTORY)
            results.append(
                {
                    "id": str(rel),
                    "title": f"{'[DIR] ' if item.is_dir() else ''}{item.name}",
                    "url": item.as_uri(),
                }
            )
    else:
        for path in ALLOWED_DIRECTORY.rglob("*"):
            try:
                rel = path.relative_to(ALLOWED_DIRECTORY)
                if normalized in path.name.lower() or normalized in str(rel).lower():
                    results.append(
                        {
                            "id": str(rel),
                            "title": f"{'[DIR] ' if path.is_dir() else ''}{path.name}",
                            "url": path.as_uri(),
                        }
                    )
            except (OSError, ValueError):
                continue

    return {"results": results[:20]}


@mcp.tool()
def fetch(id: str) -> dict[str, Any]:
    """Fetch the contents of a file or list the contents of a directory."""
    if not id:
        raise ValueError("File ID is required")

    path = validate_path(id)
    if not path.exists():
        raise ValueError(f"Not found: {id}")

    if path.is_dir():
        items = sorted(
            path.iterdir(),
            key=lambda item: (not item.is_dir(), item.name.lower()),
        )
        names = [f"{'[DIR] ' if item.is_dir() else ''}{item.name}" for item in items]
        content = f"Directory: {id}\n\nContents:\n" + "\n".join(names)
        return {
            "id": id,
            "title": path.name,
            "text": content,
            "url": path.as_uri(),
            "metadata": {"type": "directory"},
        }

    if path.stat().st_size > MAX_FILE_SIZE:
        raise ValueError("File too large (limit 1MB)")

    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        text = f"[Binary file: {path.suffix or 'unknown'}]"

    return {
        "id": id,
        "title": path.name,
        "text": text,
        "url": path.as_uri(),
        "metadata": {"type": "file", "size": path.stat().st_size},
    }


@mcp.tool()
def write_file(path: str, content: str) -> dict[str, Any]:
    """Write a UTF-8 text file inside the allowed workspace, creating parents."""
    if not path:
        raise ValueError("File path is required")

    destination = validate_path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content, encoding="utf-8")
    return {
        "success": True,
        "message": f"Wrote {len(content.encode('utf-8'))} bytes to {path}",
        "path": path,
    }


@mcp.tool()
def create_directory(path: str) -> dict[str, Any]:
    """Create a directory and any missing parent directories."""
    if not path:
        raise ValueError("Directory path is required")

    destination = validate_path(path)
    destination.mkdir(parents=True, exist_ok=True)
    return {
        "success": True,
        "message": f"Created directory: {path}",
        "path": path,
    }


@mcp.tool()
def delete_file(path: str) -> dict[str, Any]:
    """Delete a file or recursively delete a directory inside the workspace."""
    if not path:
        raise ValueError("Path is required")

    destination = validate_path(path)
    if not destination.exists():
        raise ValueError(f"Path does not exist: {path}")

    if destination == ALLOWED_DIRECTORY:
        raise PermissionError("Refusing to delete the workspace root")

    if destination.is_dir():
        shutil.rmtree(destination)
        kind = "directory"
    else:
        destination.unlink()
        kind = "file"

    return {
        "success": True,
        "message": f"Deleted {kind}: {path}",
        "path": path,
        "type": kind,
    }


@mcp.tool()
def shell(
    command: str | list[str],
    workdir: str,
    timeout: int = DEFAULT_TIMEOUT_SEC,
) -> dict[str, Any]:
    """Execute a command with its working directory restricted to the workspace."""
    working_directory = validate_path(workdir)
    if not working_directory.exists() or not working_directory.is_dir():
        raise ValueError(f"Invalid workdir: {working_directory}")

    if isinstance(command, str):
        argv = shlex.split(command)
    elif isinstance(command, list) and all(isinstance(item, str) for item in command):
        argv = command
    else:
        raise ValueError("command must be a string or an array of strings")

    if not argv:
        raise ValueError("command cannot be empty")

    timeout = max(1, int(timeout))

    try:
        proc = subprocess.run(
            argv,
            cwd=str(working_directory),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=restricted_env(),
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or f"Timed out after {timeout}s"
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        return {
            "ok": False,
            "exitCode": None,
            "timedOut": True,
            "stdout": stdout[:MAX_STDOUT_CHARS],
            "stderr": stderr[:MAX_STDERR_CHARS],
        }

    return {
        "ok": proc.returncode == 0,
        "exitCode": proc.returncode,
        "timedOut": False,
        "stdout": (proc.stdout or "")[:MAX_STDOUT_CHARS],
        "stderr": (proc.stderr or "")[:MAX_STDERR_CHARS],
    }


@mcp.tool()
def apply_patch(patch: str) -> dict[str, Any]:
    """Apply full-file replacements using Begin Patch / Update File blocks."""
    begin = "*** Begin Patch"
    end = "*** End Patch"
    update_header = "*** Update File:"

    if not patch or begin not in patch:
        raise ValueError(f"Patch missing '{begin}'")

    updated: list[str] = []
    cursor = 0

    while True:
        start = patch.find(begin, cursor)
        if start == -1:
            break

        stop = patch.find(end, start)
        if stop == -1:
            raise ValueError(f"Unclosed patch block (missing '{end}')")

        block = patch[start + len(begin):stop].strip("\n")
        cursor = stop + len(end)
        position = 0

        while True:
            header_pos = block.find(update_header, position)
            if header_pos == -1:
                break

            next_header = block.find(update_header, header_pos + len(update_header))
            section = block[
                header_pos:next_header if next_header != -1 else len(block)
            ]

            first_line_end = section.find("\n")
            if first_line_end == -1:
                raise ValueError("Malformed update header")

            header = section[:first_line_end].strip()
            relative_path = header[len(update_header):].strip()
            new_content = section[first_line_end + 1:]

            destination = validate_path(relative_path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(new_content, encoding="utf-8")
            updated.append(str(destination.relative_to(ALLOWED_DIRECTORY)))

            position = next_header if next_header != -1 else len(block)

    return {"success": True, "updated": updated}


if __name__ == "__main__":
    print(f"Starting MCP server restricted to: {ALLOWED_DIRECTORY}")
    print("MCP URL: http://localhost:8000/mcp")
    mcp.run(
        transport="streamable-http",
        host="127.0.0.1",
        port=8000,
        streamable_http_path="/mcp",
        stateless_http=True,
        json_response=True,
        transport_security=TRANSPORT_SECURITY,
    )
