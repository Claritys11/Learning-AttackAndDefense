from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Mapping

from ..integrations.tool_runner import ToolResult, ToolRunner
from .models import HttpRequest, HttpResponse

_STATUS_LINE = re.compile(r"^HTTP/\d(?:\.\d)?\s+(\d{3})\b")

def parse_http_raw(raw: str) -> tuple[int, dict[str, str], str]:
    if not raw.strip():
        return 0, {}, ""
    # curl -i can output multiple header blocks if there are 100-continue or redirects
    # We want the final status line and header block
    blocks = re.split(r"(?:\r?\n){2}", raw)
    # Find all blocks that start with HTTP/...
    header_indices = [i for i, b in enumerate(blocks) if _STATUS_LINE.match(b.strip())]
    if not header_indices:
        return 0, {}, raw
    last_header_idx = header_indices[-1]
    header_block = blocks[last_header_idx].strip()
    body = "\r\n\r\n".join(blocks[last_header_idx + 1 :])

    lines = header_block.splitlines()
    status_match = _STATUS_LINE.match(lines[0].strip())
    status_code = int(status_match.group(1)) if status_match else 0

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            key, val = line.split(":", 1)
            headers[key.strip().lower()] = val.strip()

    return status_code, headers, body

@dataclass(frozen=True)
class HttpAdapter:
    runner: ToolRunner
    binary: str = "curl"

    def execute(self, request: HttpRequest) -> tuple[ToolResult, HttpResponse]:
        url = request.url
        if not (url.startswith("http://") or url.startswith("https://")):
            url = f"http://{url}"

        cmd = [self.binary, "-s", "-S", "-i", "-X", request.method.upper()]
        timeout_int = max(1, int(request.timeout_s))
        cmd.extend(["--max-time", str(timeout_int)])

        for k, v in request.headers.items():
            cmd.extend(["-H", f"{k}: {v}"])

        if request.body is not None:
            cmd.extend(["--data-binary", request.body])

        cmd.append(url)

        res = self.runner.run(cmd, timeout_s=request.timeout_s + 2.0)
        status_code, headers, body = parse_http_raw(res.stdout)
        http_response = HttpResponse(
            status_code=status_code,
            headers=headers,
            body=body,
            duration_s=res.duration_s,
            raw_output=res.stdout,
        )
        return res, http_response

@dataclass
class HttpService:
    adapter: HttpAdapter

    def request(
        self,
        url: str,
        method: str = "GET",
        headers: Mapping[str, str] | None = None,
        body: str | None = None,
        timeout_s: float = 10.0,
    ) -> HttpResponse:
        req = HttpRequest(
            url=url,
            method=method,
            headers=headers or {},
            body=body,
            timeout_s=timeout_s,
        )
        result, resp = self.adapter.execute(req)
        if not result.success and result.error_kind != "nonzero_exit":
            raise RuntimeError(f"HTTP request failed: {result.stderr or result.error or 'unknown error'}")
        return resp

    def get(self, url: str, headers: Mapping[str, str] | None = None, timeout_s: float = 10.0) -> HttpResponse:
        return self.request(url, method="GET", headers=headers, timeout_s=timeout_s)

    def post(
        self,
        url: str,
        body: str | None = None,
        headers: Mapping[str, str] | None = None,
        timeout_s: float = 10.0,
    ) -> HttpResponse:
        return self.request(url, method="POST", headers=headers, body=body, timeout_s=timeout_s)
