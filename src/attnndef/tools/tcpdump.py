from __future__ import annotations
import os
from dataclasses import dataclass

from ..integrations.tool_runner import ToolResult, ToolRunner
from .models import PacketCaptureResult

@dataclass(frozen=True)
class TcpdumpAdapter:
    runner: ToolRunner
    binary: str = "tcpdump"

    def capture(
        self,
        *,
        interface: str = "any",
        duration_s: float = 10.0,
        packet_count: int = 100,
        bpf_filter: str = "",
        output_pcap: str | None = None,
    ) -> tuple[ToolResult, PacketCaptureResult]:
        if duration_s <= 0 or duration_s > 300:
            raise ValueError("capture duration must be between 1 and 300 seconds")
        if packet_count <= 0 or packet_count > 10000:
            raise ValueError("packet count must be between 1 and 10000")

        cmd = [self.binary, "-n", "-i", interface]
        if packet_count:
            cmd.extend(["-c", str(packet_count)])
        if output_pcap:
            cmd.extend(["-w", os.path.expanduser(output_pcap)])

        if bpf_filter.strip():
            cmd.append(bpf_filter.strip())

        # ToolRunner timeout terminates the process group if packet_count hasn't triggered yet
        result = self.runner.run(cmd, timeout_s=duration_s)
        cap_result = PacketCaptureResult(
            interface=interface,
            packet_count=packet_count,
            filter_bpf=bpf_filter,
            raw_output=result.stdout + ("\n" + result.stderr if result.stderr else ""),
            duration_s=result.duration_s,
            pcap_path=output_pcap,
        )
        return result, cap_result

@dataclass
class TcpdumpService:
    adapter: TcpdumpAdapter

    def capture_live(
        self,
        *,
        interface: str = "any",
        duration_s: float = 5.0,
        packet_count: int = 50,
        bpf_filter: str = "",
        output_pcap: str | None = None,
    ) -> PacketCaptureResult:
        result, cap_result = self.adapter.capture(
            interface=interface,
            duration_s=duration_s,
            packet_count=packet_count,
            bpf_filter=bpf_filter,
            output_pcap=output_pcap,
        )
        return cap_result
