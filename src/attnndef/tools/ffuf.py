from __future__ import annotations
import json
import os
import tempfile
from dataclasses import dataclass
from typing import Sequence

from ..integrations.tool_runner import ToolResult, ToolRunner
from .models import FfufMatch, FfufScanResult

def parse_ffuf_json(raw: str) -> tuple[FfufMatch, ...]:
    if not raw.strip():
        return ()
    matches: list[FfufMatch] = []
    try:
        data = json.loads(raw)
        results = data.get("results", []) if isinstance(data, dict) else []
        for r in results:
            matches.append(
                FfufMatch(
                    url=str(r.get("url", "")),
                    status=int(r.get("status", 0)),
                    length=int(r.get("length", 0)),
                    words=int(r.get("words", 0)),
                    lines=int(r.get("lines", 0)),
                    redirect_location=str(r.get("redirectlocation", "")),
                )
            )
        return tuple(matches)
    except json.JSONDecodeError:
        # Fallback for line-delimited JSON
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
                if "url" in r and "status" in r:
                    matches.append(
                        FfufMatch(
                            url=str(r.get("url", "")),
                            status=int(r.get("status", 0)),
                            length=int(r.get("length", 0)),
                            words=int(r.get("words", 0)),
                            lines=int(r.get("lines", 0)),
                            redirect_location=str(r.get("redirectlocation", "")),
                        )
                    )
            except json.JSONDecodeError:
                continue
        return tuple(matches)

@dataclass(frozen=True)
class FfufAdapter:
    runner: ToolRunner
    binary: str = "ffuf"

    def fuzz(
        self,
        url: str,
        wordlist_path: str,
        *,
        extensions: Sequence[str] = (),
        match_codes: str = "200,204,301,302,307,401,403",
        timeout_s: float = 30.0,
    ) -> tuple[ToolResult, tuple[FfufMatch, ...]]:
        target_url = url if "FUZZ" in url else f"{url.rstrip('/')}/FUZZ"

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            cmd = [
                self.binary,
                "-u", target_url,
                "-w", wordlist_path,
                "-mc", match_codes,
                "-o", tmp_path,
                "-of", "json",
                "-s",
            ]
            if extensions:
                ext_str = ",".join(f".{e.lstrip('.')}" for e in extensions if e.strip())
                if ext_str:
                    cmd.extend(["-e", ext_str])

            result = self.runner.run(cmd, timeout_s=timeout_s)

            output_content = ""
            if os.path.exists(tmp_path):
                with open(tmp_path, encoding="utf-8", errors="replace") as f:
                    output_content = f.read()

            # If output file is empty, try stdout
            if not output_content.strip() and result.stdout.strip():
                output_content = result.stdout

            matches = parse_ffuf_json(output_content)
            return result, matches
        finally:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

@dataclass
class FfufService:
    adapter: FfufAdapter

    def discover_endpoints(
        self,
        url: str,
        wordlist_path: str,
        *,
        extensions: Sequence[str] = (),
        match_codes: str = "200,204,301,302,307,401,403",
        timeout_s: float = 30.0,
    ) -> FfufScanResult:
        if not os.path.exists(wordlist_path):
            raise FileNotFoundError(f"wordlist not found: {wordlist_path}")

        result, matches = self.adapter.fuzz(
            url,
            wordlist_path,
            extensions=extensions,
            match_codes=match_codes,
            timeout_s=timeout_s,
        )
        return FfufScanResult(
            target_url=url,
            wordlist=wordlist_path,
            matches=matches,
            duration_s=result.duration_s,
            raw_output=result.stdout,
        )
