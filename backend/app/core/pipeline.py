"""拾音工坊核心管道：log_source→parser_rule→ingest_job→event_store 端到端采集解析链路。

数据流：原始日志行 → 格式校验 → 正则解析 → 字段提取 → 事件存储
涉及模块：log_source, parser_rule, ingest_job, event_store, batch_checkpoint

身份与一致性约定（修复跨主机事件编号冲突、断线重采重复写入）：
- 事件身份由「来源编号 + 来源内行号」构成的 source_line_key 决定，与主机名、
  文本内容、内存计数器均无关；不同来源或同文件不同位置的日志分别计数。
- 入库按 source_line_key 幂等：重复提交同一源行只保留一份事件，重采不重复写入。
- 确认批次生成完整事件清单（ConfirmedManifest），采集作业凭持久化清单续采。
- 解析更正必须绑定旧原行字节（raw_checksum）与旧分类依据，位置相同但字节不符
  或依据不符的修订一律拒绝，且只修订该源行对应的唯一事件。
- 一轮回放只认一个完整确认的分类版本；已领用的旧清单只能结案或明确交回。
- 回放结果按清单逐行核销：成功才计入来源进度，失败保留待处理，重送结果幂等。
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.core.models import (
    BatchCheckpoint, ClassificationBasis, ConfirmedEvent, ConfirmedManifest,
    EventRecord, EventTypeDef, IngestJob, IngestMetric, LogEntry,
    LogSourceConfig, ParseCorrection, ParseResultStatus, ParseRule,
    QualityReport, ReplayClaim, ReplayResult, SourceProgress,
)

# ---------- 身份工具：标准化与入库共享同一套来源身份 ----------


def build_source_line_key(source_id: str, line_no: int) -> str:
    """来源行身份键：同一来源同一行的任何重送/更正都命中同一身份。"""
    return f"{source_id}#L{line_no}"


def compute_raw_checksum(source_id: str, line_no: int, raw_line: str) -> str:
    """原文字节校验值——更正时用于证明「位置没变且原文字节一致」。"""
    blob = f"{source_id}|{line_no}|{raw_line}".encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def make_event_record_id(source_line_key: str) -> str:
    """由来源身份派生确定性事件编号：跨主机首行相同也不会撞号，重采编号稳定。"""
    digest = hashlib.sha256(source_line_key.encode("utf-8")).hexdigest()[:12].upper()
    return f"EVEN-{digest}"


# ---------- 预置日志来源配置 ----------

PRESET_LOG_SOURCES: dict[str, LogSourceConfig] = {
    "access-web": LogSourceConfig(
        source_id="LOG_-0001",
        source_name="WebAccessLog",
        app_label="web-gateway",
        log_path="/var/log/nginx/access.log",
        log_format="access",
        encoding="utf-8",
        collect_method="file_tail",
        access_state="已接入",
    ),
    "app-backend": LogSourceConfig(
        source_id="LOG_-0002",
        source_name="BackendAppLog",
        app_label="backend-api",
        log_path="/var/log/app/backend.log",
        log_format="app",
        encoding="utf-8",
        collect_method="file_tail",
        access_state="已接入",
    ),
    "sys-auth": LogSourceConfig(
        source_id="LOG_-0003",
        source_name="SysAuthLog",
        app_label="auth-service",
        log_path="/var/log/auth/syslog",
        log_format="sys",
        encoding="utf-8",
        collect_method="file_tail",
        access_state="已接入",
    ),
}

# ---------- 预置解析规则 ----------

PRESET_PARSE_RULES: list[ParseRule] = [
    ParseRule(
        rule_id="PARS-0001",
        source_id="LOG_-0001",
        regex_pattern=r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+HTTP/\d\.\d"\s+(\d{3})\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"$',
        field_names=["client_ip", "time_local", "method", "url", "status", "body_bytes", "referer", "user_agent"],
        time_format="%d/%b/%Y:%H:%M:%S %z",
        priority=10,
        state="生效中",
    ),
    ParseRule(
        rule_id="PARS-0002",
        source_id="LOG_-0002",
        regex_pattern=r'^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\.\d{3})\s+\[([^\]]+)\]\s+(INFO|WARN|ERROR|DEBUG)\s+(\S+)\s+-\s+(.*)$',
        field_names=["timestamp", "thread", "level", "logger", "message"],
        time_format="%Y-%m-%d %H:%M:%S.%f",
        priority=10,
        state="生效中",
    ),
    ParseRule(
        rule_id="PARS-0003",
        source_id="LOG_-0003",
        regex_pattern=r'^([\w-]+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+([\w-]+)\s+([\w-]+)\[(\d+)\]:\s+(\w+)\s+(.*)$',
        field_names=["sys_time", "hostname", "process", "pid", "action", "detail"],
        time_format="%b %d %H:%M:%S",
        priority=10,
        state="生效中",
    ),
]

# ---------- 预置事件类型 ----------

PRESET_EVENT_TYPES: dict[str, EventTypeDef] = {
    "access": EventTypeDef(
        type_id="EVEN-0001", type_name="访问事件",
        category_tag="access", severity="INFO",
        sample_ratio=0.5, retain_days=30,
    ),
    "error": EventTypeDef(
        type_id="EVEN-0002", type_name="错误事件",
        category_tag="error", severity="HIGH",
        sample_ratio=1.0, retain_days=90,
    ),
    "auth": EventTypeDef(
        type_id="EVEN-0003", type_name="认证事件",
        category_tag="auth", severity="MEDIUM",
        sample_ratio=1.0, retain_days=60,
    ),
}


@dataclass
class IngestPipelineState:
    """采集管道运行时状态——跨模块数据流的中间产物。"""
    source: LogSourceConfig
    rule: ParseRule
    job: IngestJob
    parsed_logs: list[LogEntry]
    events: list[EventRecord]
    errors: list[dict[str, Any]]
    checkpoints: list[BatchCheckpoint]
    metric: IngestMetric
    quality_report: QualityReport | None = None


class IngestPipeline:
    """核心采集管道：log_source → parser_rule → ingest_job → event_store。

    单次管道执行：
    1. 从 log_source 获取原始日志行
    2. 使用 parser_rule 逐行解析
    3. 通过 ingest_job 控制采集批次
    4. 生成 EventRecord 写入 event_store（按来源身份幂等）
    5. 产出 batch_checkpoint 支持断点恢复
    6. 产出 ingest_metric 作为质量报告的数据源
    """

    def __init__(self):
        self._checkpoint_store: dict[str, BatchCheckpoint] = {}
        # 兼容视图：来源主机 -> 事件列表
        self._event_store: dict[str, list[EventRecord]] = {}
        # 主身份索引：source_line_key -> 唯一事件，重采/重送只命中这一份
        self._event_index: dict[str, EventRecord] = {}
        self._fingerprint_seen: set[str] = set()
        # 确认清单与重放认领
        self._manifests: dict[str, ConfirmedManifest] = {}
        self._manifests_by_source: dict[str, list[str]] = {}
        self._claims: dict[str, ReplayClaim] = {}
        # 持久来源证据：续采与核销一律以此为准，而非内存计数器
        self._progress: dict[str, SourceProgress] = {}
        self._classification_versions: dict[str, int] = {}
        self._correction_seq: dict[str, int] = {}
        self._audit: list[dict[str, Any]] = []

    # ---------- 数据流 1: log_source → parser_rule → ingest_job → event_store ----------

    def parse_raw_lines(self, source: LogSourceConfig, raw_lines: list[str]) -> list[LogEntry]:
        """用来源配置校验原始日志行格式。"""
        entries: list[LogEntry] = []
        for i, line in enumerate(raw_lines):
            if not line.strip():
                continue
            if not source.match_format(line):
                entries.append(LogEntry(
                    raw_line=line, line_number=i + 1, source_id=source.source_id,
                    parse_status=ParseResultStatus.FORMAT_MISMATCH,
                ))
                continue
            entries.append(LogEntry(
                raw_line=line, line_number=i + 1, source_id=source.source_id,
            ))
        return entries

    def apply_parse_rules(self, entries: list[LogEntry], rule: ParseRule) -> list[LogEntry]:
        """用解析规则从日志条目中提取字段。"""
        for entry in entries:
            if entry.parse_status == ParseResultStatus.FORMAT_MISMATCH:
                continue
            status, fields = rule.parse(entry.raw_line)
            entry.parse_status = status
            entry.parsed_fields = fields or {}
            entry.checksum = entry.compute_checksum()
        return entries

    def run_ingest_job(self, entries: list[LogEntry], job: IngestJob) -> list[LogEntry]:
        """执行采集作业：按 batch_size 分批，追踪文件游标和跳过行数。"""
        processed: list[LogEntry] = []
        for entry in entries:
            if job.processed_lines >= job.batch_size:
                break
            if entry.parse_status == ParseResultStatus.FORMAT_MISMATCH:
                job.skipped_lines += 1
                processed.append(entry)
                continue
            job.processed_lines += 1
            job.file_cursor += len(entry.raw_line.encode("utf-8"))
            processed.append(entry)
        return processed

    def classify_events(self, entries: list[LogEntry],
                        rule: ParseRule | None = None) -> list[EventRecord]:
        """将解析后的日志条目按事件类型分类并生成带稳定身份的 EventRecord。

        数据流入口：event_store ← 解析后的 LogEntry
        分类依据：日志级别（app log → error/access）或来源标识
        身份依据：source_id + line_number 派生的 source_line_key，
        与主机名和文本内容无关——两个来源首行文本相同也各自独立编号。
        """
        records: list[EventRecord] = []
        for entry in entries:
            if entry.parse_status != ParseResultStatus.OK or not entry.parsed_fields:
                continue
            event_type, basis = self._classify_entry(entry, rule)
            source_line_key = build_source_line_key(entry.source_id, entry.line_number)
            raw_checksum = compute_raw_checksum(
                entry.source_id, entry.line_number, entry.raw_line,
            )
            host = (
                entry.parsed_fields.get("client_ip")
                or entry.parsed_fields.get("hostname")
                or "unknown"
            )
            record = EventRecord(
                record_id=make_event_record_id(source_line_key),
                event_type=event_type,
                original_content=entry.raw_line[:500],
                parsed_fields=dict(entry.parsed_fields),
                masked_fields={},
                enriched_fields={},
                event_time=entry.event_time or datetime.now(),
                source_host=host,
                store_partition=f"{datetime.now():%Y%m%d}",
                index_state="已写入",
                source_id=entry.source_id,
                source_line_no=entry.line_number,
                source_line_key=source_line_key,
                raw_checksum=raw_checksum,
                classification_basis=basis,
            )
            records.append(record)
        return records

    def store_events(self, records: list[EventRecord]) -> int:
        """写入 event_store 并返回**新写入**条数（重复提交幂等，不重复计数）。"""
        return self.store_events_detail(records)["stored"]

    def store_events_detail(self, records: list[EventRecord]) -> dict[str, Any]:
        """按来源身份幂等入库，返回入库明细。

        - 同一 source_line_key 重复提交（断线补采/回执丢失重试）只保留一份事件；
        - 不同来源或同文件不同位置的日志分别计数、各自入库。
        """
        stored = 0
        duplicated: list[str] = []
        stored_keys: list[str] = []
        for record in records:
            key = record.source_line_key or self._fallback_key(record)
            if not record.source_line_key:
                # 补全身份字段，保证后续更正/核销可用
                record.source_line_key = key
            existing = self._event_index.get(key)
            if existing is not None:
                # 重采命中同一来源行：保留原事件，不重复写入库存列表
                duplicated.append(key)
                self._append_audit("store_duplicate_skipped", source_line_key=key,
                            record_id=existing.record_id)
                continue
            record.source_line_key = key
            if not record.raw_checksum:
                record.raw_checksum = compute_raw_checksum(
                    record.source_id, record.source_line_no, record.original_content,
                )
            self._event_index[key] = record
            self._event_store.setdefault(record.source_host, []).append(record)
            progress = self._progress.setdefault(
                record.source_id, SourceProgress(source_id=record.source_id),
            )
            progress.processed_line_keys.add(key)
            stored += 1
            stored_keys.append(key)
        self._append_audit("store_events", stored=stored, duplicated=len(duplicated))
        return {
            "stored": stored,
            "duplicated": len(duplicated),
            "stored_keys": stored_keys,
            "duplicate_keys": duplicated,
        }

    def _fallback_key(self, record: EventRecord) -> str:
        """无来源行号的兜底身份（仍对同一内容的重送保持稳定）。"""
        if record.source_id and record.source_line_no:
            return build_source_line_key(record.source_id, record.source_line_no)
        digest = hashlib.sha256(
            f"{record.source_id}|{record.original_content}".encode("utf-8")
        ).hexdigest()[:12]
        return f"{record.source_id or 'NA'}#F{digest}"

    # ---------- 确认批次：事件存储把确认清单交给采集作业续采 ----------

    def confirm_batch(self, source_id: str,
                      records: list[EventRecord] | None = None) -> ConfirmedManifest:
        """将一批事件确认为完整分类版本，生成可续采的事件清单。

        一轮只认一个完整确认的分类版本：若该来源已有领用中的清单，
        必须先结案或交回，才能确认新版本。
        """
        active = self._active_claim(source_id)
        if active is not None:
            raise RuntimeError(
                f"来源 {source_id} 存在领用中的清单 {active.manifest_id}，"
                "请先结案或交回旧分类版本后再确认新版本"
            )
        if records is None:
            records = [
                event for key, event in self._event_index.items()
                if event.source_id == source_id and not event.classification_version
            ]
        else:
            records = [r for r in records if r.source_id == source_id]
        if not records:
            raise ValueError(f"来源 {source_id} 没有可确认的事件")

        self._classification_versions[source_id] = (
            self._classification_versions.get(source_id, 0) + 1
        )
        version = f"CLS-{source_id}-{self._classification_versions[source_id]:04d}"

        events: list[ConfirmedEvent] = []
        for record in records:
            record.classification_version = version
            events.append(ConfirmedEvent(
                source_line_key=record.source_line_key,
                source_id=record.source_id,
                source_line_no=record.source_line_no,
                record_id=record.record_id,
                raw_checksum=record.raw_checksum,
                original_content=record.original_content,
                event_type_id=record.event_type.type_id,
                classification_version=version,
                classification_basis=record.classification_basis or ClassificationBasis(),
            ))

        # 旧的未领用确认清单被新版本取代；已交回/已结案的清单保留其历史状态，
        # 不允许同一来源同时存在两份「可领用」清单。
        supersedes = ""
        for old_id in self._manifests_by_source.get(source_id, []):
            old = self._manifests[old_id]
            if old.state == "已确认":
                old.state = "已作废"
                supersedes = old.classification_version
        manifest = ConfirmedManifest(
            manifest_id=f"MANI-{source_id}-{self._classification_versions[source_id]:04d}",
            source_id=source_id,
            classification_version=version,
            events=events,
            state="已确认",
            supersedes_version=supersedes,
        )
        self._manifests[manifest.manifest_id] = manifest
        self._manifests_by_source.setdefault(source_id, []).append(manifest.manifest_id)
        self._append_audit("confirm_batch", manifest_id=manifest.manifest_id,
                    source_id=source_id, version=version, count=len(events))
        return manifest

    def claim_manifest(self, source_id: str,
                       manifest_id: str | None = None) -> ReplayClaim:
        """值班人员领用确认清单开始回放；已交回的清单可被重新领用。"""
        manifest = self._resolve_manifest(source_id, manifest_id)
        if manifest is None:
            raise ValueError(f"来源 {source_id} 没有可领用的确认清单")
        if manifest.state not in ("已确认", "已交回"):
            raise RuntimeError(
                f"清单 {manifest.manifest_id} 当前状态为「{manifest.state}」，不可领用"
            )
        claim = ReplayClaim(
            claim_id=f"CLAM-{manifest.manifest_id}-{len(self._claims) + 1:04d}",
            manifest_id=manifest.manifest_id,
            source_id=source_id,
            classification_version=manifest.classification_version,
        )
        manifest.state = "已领用"
        manifest.claim = claim
        self._claims[claim.claim_id] = claim
        self._append_audit("claim_manifest", claim_id=claim.claim_id,
                    manifest_id=manifest.manifest_id, version=claim.classification_version)
        return claim

    def release_claim(self, claim_id: str) -> ReplayClaim:
        """明确交回已领用的旧分类清单，交回后可重新领取新版本。"""
        claim = self._claims.get(claim_id)
        if claim is None:
            raise ValueError(f"认领记录 {claim_id} 不存在")
        if claim.state != "已领用":
            raise RuntimeError(f"认领 {claim_id} 已处于「{claim.state}」，无需交回")
        claim.state = "已交回"
        manifest = self._manifests[claim.manifest_id]
        manifest.state = "已交回"
        self._append_audit("release_claim", claim_id=claim_id, manifest_id=manifest.manifest_id)
        return claim

    def get_replay_eligibility(self, source_id: str, source_line_key: str) -> dict[str, Any]:
        """检查某源行的原回放资格：版本一致且未核销才可继续，否则需重新领取。"""
        claim = self._active_claim(source_id)
        event = self._event_index.get(source_line_key)
        if claim is None:
            return {"eligible": False, "reason": "无领用中的回放清单",
                    "need_reclaim": True}
        if event is None:
            return {"eligible": False, "reason": "事件尚未入库",
                    "need_reclaim": False, "claim_id": claim.claim_id}
        progress = self._progress.get(source_id)
        if progress and source_line_key in progress.replayed_line_keys:
            return {"eligible": False, "reason": "该行已核销，任何时点只结算一次",
                    "need_reclaim": False, "claim_id": claim.claim_id,
                    "settled_version": progress.settled_version}
        if event.classification_version != claim.classification_version:
            return {
                "eligible": False,
                "reason": (
                    f"分类版本已由 {claim.classification_version} "
                    f"更新为 {event.classification_version}，原回放不可继续，需重新领取"
                ),
                "need_reclaim": True,
                "claim_id": claim.claim_id,
                "claimed_version": claim.classification_version,
                "current_version": event.classification_version,
            }
        return {
            "eligible": True,
            "reason": "原回放可继续",
            "need_reclaim": False,
            "claim_id": claim.claim_id,
            "version": claim.classification_version,
        }

    def apply_replay_results(self, results: list[ReplayResult]) -> dict[str, Any]:
        """按确认清单逐行核销回放结果。

        - A 成功、B 失败：只把 A 归入来源进度，B 保留待处理；
        - 重送同一结果幂等，A 的完成数不会再加一；
        - 失败不计入完成数，之后的更正也不会抹掉 B 的失败记录。
        """
        succeeded = 0
        failed = 0
        duplicate = 0
        invalid = 0
        pending: list[str] = []
        for result in results:
            manifest = self._manifests.get(result.manifest_id)
            if manifest is None or manifest.claim is None:
                invalid += 1
                self._append_audit("replay_invalid", source_line_key=result.source_line_key,
                            manifest_id=result.manifest_id, reason="清单不存在")
                continue
            if manifest.claim.state != "已领用":
                invalid += 1
                self._append_audit("replay_invalid", source_line_key=result.source_line_key,
                            manifest_id=result.manifest_id,
                            reason=f"清单状态为{manifest.state}，不可核销")
                continue
            if manifest.find_event(result.source_line_key) is None:
                invalid += 1
                self._append_audit("replay_invalid", source_line_key=result.source_line_key,
                            manifest_id=result.manifest_id, reason="该行不在确认清单内")
                continue
            # 版本守卫：事件已被更正到新分类版本时，旧清单的核销必须拒绝，
            # 值班人员需先交回旧清单、重新领取新版本后才能回放。
            live_event = self._event_index.get(result.source_line_key)
            if (live_event is not None
                    and live_event.classification_version
                    != manifest.classification_version):
                invalid += 1
                self._append_audit(
                    "replay_invalid", source_line_key=result.source_line_key,
                    manifest_id=result.manifest_id,
                    reason=(
                        f"分类版本漂移：清单版本 {manifest.classification_version}，"
                        f"事件当前版本 {live_event.classification_version}，需重新领取"
                    ),
                )
                continue
            progress = self._progress.setdefault(
                result.source_id, SourceProgress(source_id=result.source_id),
            )
            key = result.source_line_key
            if key in progress.replayed_line_keys:
                # 重送同一处理结果：幂等丢弃，完成数不重复累计
                duplicate += 1
                self._append_audit("replay_duplicate_ignored", source_line_key=key,
                            manifest_id=result.manifest_id)
                continue
            if result.success:
                progress.replayed_line_keys.add(key)
                progress.replay_success_count += 1
                succeeded += 1
                self._append_audit("replay_settled", source_line_key=key,
                            manifest_id=result.manifest_id, success=True)
            else:
                # 失败保留待处理：不进入已核销集合、不增加完成数
                progress.failed_line_keys.add(key)
                failed += 1
                pending.append(key)
                self._append_audit("replay_failed_pending", source_line_key=key,
                            manifest_id=result.manifest_id, detail=result.detail)
        return {
            "settled": succeeded,
            "succeeded": succeeded,
            "failed": failed,
            "duplicate_ignored": duplicate,
            "invalid": invalid,
            "pending_keys": pending,
        }

    def settle_replay(self, claim_id: str) -> ReplayClaim:
        """结算一轮回放：任何时点只能结算一次，并记录进入结算的分类版本。"""
        claim = self._claims.get(claim_id)
        if claim is None:
            raise ValueError(f"认领记录 {claim_id} 不存在")
        progress = self._progress.setdefault(
            claim.source_id, SourceProgress(source_id=claim.source_id),
        )
        if claim.state == "已结案":
            # 幂等：重复结算请求直接返回既有结案记录
            return claim
        if progress.settled_claim_id:
            raise RuntimeError(
                f"来源 {claim.source_id} 已由认领 {progress.settled_claim_id} "
                f"按版本 {progress.settled_version} 结算，不能重复结算"
            )
        claim.state = "已结案"
        claim.closed_at = datetime.now()
        claim.settled_results = progress.replay_success_count
        claim.settled_version = claim.classification_version
        manifest = self._manifests[claim.manifest_id]
        manifest.state = "已结案"
        progress.settled_claim_id = claim.claim_id
        progress.settled_version = claim.classification_version
        progress.settled_at = claim.closed_at
        self._append_audit("settle_replay", claim_id=claim_id,
                    manifest_id=manifest.manifest_id,
                    version=claim.settled_version,
                    settled_results=claim.settled_results)
        return claim

    # ---------- 解析更正：绑定旧原行字节与旧分类依据 ----------

    def apply_parse_correction(self, correction: ParseCorrection) -> EventRecord:
        """应用同一源行的解析更正，只修订该 source_line_key 对应的唯一事件。

        拒绝条件：
        - 位置相同但原文字节不符（raw_checksum 或原行内容不一致）；
        - 更正携带的旧分类依据与持久证据不符；
        - 该源行事件尚不存在（更正不能凭空创建事件）。
        更正不触碰来源进度：B 的失败不会被抹掉，A 的完成数不会变化。
        """
        key = build_source_line_key(correction.source_id, correction.source_line_no)
        event = self._event_index.get(key)
        if event is None:
            raise ValueError(f"源行 {key} 的事件不存在，无法更正（更正不能新建事件）")
        if event.original_content != correction.expected_raw_line:
            raise ValueError(
                f"源行 {key} 原文字节与更正请求绑定的旧原行不符，拒绝修订"
            )
        if event.raw_checksum != correction.expected_raw_checksum:
            raise ValueError(
                f"源行 {key} 原行校验值不符（位置未变但原文字节已变化），拒绝修订"
            )
        if not (event.classification_basis or ClassificationBasis()).matches(
            correction.expected_basis
        ):
            raise ValueError(
                f"源行 {key} 的旧分类依据与更正请求绑定的依据不一致，拒绝修订"
            )

        new_raw = correction.new_raw_line or event.original_content
        event.original_content = new_raw[:500]
        event.parsed_fields = dict(correction.new_parsed_fields)
        event.raw_checksum = compute_raw_checksum(
            correction.source_id, correction.source_line_no, new_raw,
        )
        new_type, new_basis = self._classify_fields(
            correction.new_parsed_fields,
            rule_id=correction.expected_basis.rule_id,
        )
        event.event_type = new_type
        event.classification_basis = new_basis

        self._correction_seq[correction.source_id] = (
            self._correction_seq.get(correction.source_id, 0) + 1
        )
        seq = self._correction_seq[correction.source_id]
        new_version = f"CLS-{correction.source_id}-CORR-{seq:04d}"
        old_version = event.classification_version
        event.classification_version = new_version
        correction.correction_id = f"CORR-{correction.source_id}-{seq:04d}"

        # 已领用的旧清单不被强行关闭：资格检查会判定需重新领取，由值班人员结案或交回
        self._append_audit("parse_correction_applied", correction_id=correction.correction_id,
                    source_line_key=key, record_id=event.record_id,
                    old_version=old_version, new_version=new_version,
                    new_type_id=new_type.type_id)
        return event

    # ---------- 采集作业凭确认清单续采 ----------

    def resume_job_with_manifest(self, job: IngestJob) -> dict[str, Any]:
        """事件存储把确认批次的事件清单交给采集作业，作业据此判断续采方式。

        返回：清单内容、领用状态、原回放能否继续、是否需要重新领取、待处理源行。
        """
        manifest_ids = self._manifests_by_source.get(job.source_id, [])
        if not manifest_ids:
            return {"resume": False, "reason": "该来源尚无确认批次清单",
                    "source_id": job.source_id}
        manifest = self._manifests[manifest_ids[-1]]
        progress = self._progress.get(job.source_id)
        replayed = progress.replayed_line_keys if progress else set()
        pending_events = [
            item for item in manifest.events
            if item.source_line_key not in replayed
        ]
        claim = manifest.claim
        need_reclaim = False
        can_continue = False
        if claim is not None and claim.state == "已领用":
            current_versions = {
                item.source_line_key: self._event_index[item.source_line_key].classification_version
                for item in manifest.events
                if item.source_line_key in self._event_index
            }
            stale = [
                k for k, ver in current_versions.items()
                if ver != claim.classification_version
            ]
            need_reclaim = bool(stale)
            can_continue = not stale
        return {
            "resume": True,
            "source_id": job.source_id,
            "job_id": job.job_id,
            "manifest_id": manifest.manifest_id,
            "classification_version": manifest.classification_version,
            "manifest_state": manifest.state,
            "claim_id": claim.claim_id if claim else None,
            "claim_state": claim.state if claim else None,
            "can_continue_replay": can_continue,
            "need_reclaim": need_reclaim,
            "events": [item.__dict__ for item in manifest.events],
            "pending_keys": [item.source_line_key for item in pending_events],
            "replayed_count": len(replayed),
        }

    # ---------- 数据流 2: ingest_job → batch_checkpoint（断点恢复） ----------

    def create_checkpoint(self, job: IngestJob, file_path: str, lines: list[str]) -> BatchCheckpoint:
        """为采集作业创建批次检查点——支持断点恢复。

        记录：文件偏移量、已处理行数、内容校验哈希（用最后 N 行拼接）。
        """
        last_blob = "".join(l.raw_line for l in lines[-5:]) if lines else ""
        content_hash = hashlib.sha256(
            f"{file_path}|{job.file_cursor}|{last_blob}".encode()
        ).hexdigest()[:16]
        checkpoint = BatchCheckpoint(
            checkpoint_id=f"BATC-{job.job_id}-{job.processed_lines:06d}",
            job_id=job.job_id,
            file_path=file_path,
            byte_offset=job.file_cursor,
            line_count=job.processed_lines + job.skipped_lines,
            content_hash=content_hash,
            state="已记录",
        )
        self._checkpoint_store[checkpoint.checkpoint_id] = checkpoint
        return checkpoint

    def resume_from_checkpoint(self, checkpoint: BatchCheckpoint) -> int:
        """从检查点恢复采集：返回应从此偏移量继续的文件位置。"""
        return checkpoint.byte_offset

    # ---------- 数据流 4: event_type → dedup_filter → sample_job ----------

    def dedup_events(self, records: list[EventRecord], dedup_fields: list[str]) -> list[EventRecord]:
        """对事件记录集合执行去重过滤——对应 dedup_filter 模块。

        使用 SHA256 指纹算法，基于指定的去重字段生成指纹。
        """
        seen: set[str] = set()
        unique: list[EventRecord] = []
        for record in records:
            key_parts = [record.event_type.type_id]
            for field in sorted(dedup_fields):
                val = record.parsed_fields.get(field, "")
                key_parts.append(f"{field}={val}")
            fp = hashlib.sha256("|".join(key_parts).encode()).hexdigest()
            if fp in seen:
                continue
            seen.add(fp)
            unique.append(record)
        return unique

    def sample_events(self, records: list[EventRecord], sample_ratio: float,
                      merge_key: str = "") -> list[EventRecord]:
        """采样归并——对应 sample_job 模块。

        按 sample_ratio 采样，按 merge_key 归并（同 key 仅保留最新）。
        """
        sampled: list[EventRecord] = []
        merged: dict[str, EventRecord] = {}
        threshold = int(len(records) * sample_ratio)
        for i, record in enumerate(records):
            if merge_key:
                mkey = record.parsed_fields.get(merge_key, "")
                if mkey:
                    merged[mkey] = record
            if i < threshold:
                sampled.append(record)
        if merge_key:
            return list(merged.values())
        return sampled

    # ---------- 数据流 6: archive_policy → event_store ----------

    def apply_archive_policy(self, partition: str, retain_days: int) -> list[str]:
        """归档策略：标记超过保留天数的分区为可归档。"""
        to_archive: list[str] = []
        cutoff_date = datetime.now() - __import__("datetime").timedelta(days=retain_days)
        cutoff_int = int(cutoff_date.strftime("%Y%m%d"))
        for host, records in self._event_store.items():
            for record in records:
                try:
                    partition_int = int(record.store_partition) if record.store_partition else 99999999
                except ValueError:
                    continue
                if partition_int < cutoff_int:
                    to_archive.append(record.record_id)
                    record.index_state = "已归档"
        return to_archive

    # ---------- 数据流 7: schema_version → parser_rule ----------

    def detect_schema_change(self, old_fields: list[str], new_fields: list[str]) -> dict[str, Any]:
        """检测Schema版本变更对解析规则的影响。

        返回变更详情：兼容/不兼容判定、新增/删除字段清单、影响事件数。
        """
        old_set = set(old_fields or [])
        new_set = set(new_fields or [])
        added = list(new_set - old_set)
        removed = list(old_set - new_set)
        is_compatible = len(removed) == 0
        affected = sum(
            len(records)
            for records in self._event_store.values()
        )
        return {
            "added_fields": added,
            "removed_fields": removed,
            "is_compatible": is_compatible,
            "affected_event_count": affected,
            "version_time": datetime.now().isoformat(),
        }

    # ---------- 数据流 8: ingest_job → ingest_metric → quality_report ----------

    def compute_ingest_metrics(self, job: IngestJob, elapsed_ms: float,
                                total_lines: int) -> IngestMetric:
        """从采集作业运行状态计算采集指标。

        采集速率 = 处理行数 / 耗时(s)
        错误率 = 跳过行数 / 总行数
        积压行数 = 总行数 - 处理行数
        """
        elapsed_s = max(elapsed_ms / 1000.0, 0.001)
        rate = job.processed_lines / elapsed_s
        error_rate = job.skipped_lines / total_lines if total_lines > 0 else 0.0
        backlog = total_lines - job.processed_lines - job.skipped_lines
        return IngestMetric(
            metric_id=f"INGE-{job.job_id}-{int(time.time())}",
            source_id=job.source_id,
            ingest_rate=round(rate, 2),
            process_delay_ms=round(elapsed_ms, 2),
            error_rate=round(error_rate, 4),
            backlog_lines=max(backlog, 0),
        )

    def generate_quality_report(self, metric: IngestMetric,
                                 parse_ok: int, parse_total: int,
                                 fields_coverage: float,
                                 processed: int = 0,
                                 skipped: int = 0) -> QualityReport:
        """从采集指标生成质量报告——对应 quality_report 模块。

        完整率 = 处理行数 / (处理+跳过)
        解析成功率 = 成功解析行数 / 总处理行数
        字段覆盖率 = 已填充字段数 / 期望字段总数
        """
        total = processed + skipped
        completeness = processed / total if total > 0 else 0.0
        parse_rate = parse_ok / parse_total if parse_total > 0 else 0.0
        return QualityReport(
            report_id=f"QUAL-{metric.metric_id}",
            source_id=metric.source_id,
            completeness_rate=round(completeness, 4),
            parse_success_rate=round(parse_rate, 4),
            field_coverage_rate=round(fields_coverage, 4),
            time_delay_seconds=metric.process_delay_ms / 1000.0,
            eval_period="hourly",
            state="已生成",
        )

    # ---------- 数据流 5: event_type → anomaly_rule → forward_rule ----------

    def check_anomaly(self, records: list[EventRecord], event_type_id: str,
                       threshold: int) -> list[EventRecord]:
        """异常检测：统计指定事件类型数量，触发告警条件。

        对应 anomaly_rule 模块：事件分类→异常告警路径。
        """
        matched = [r for r in records if r.event_type.type_id == event_type_id]
        if len(matched) > threshold:
            for r in matched:
                r.parsed_fields["anomaly_alert"] = "triggered"
        return matched

    def apply_forward_rules(self, records: list[EventRecord],
                             target: str) -> list[dict[str, Any]]:
        """编组转发规则：按目标地址组织事件批次——对应 forward_rule 模块。

        返回按目标地址分组的转发批次，供外部消费。
        """
        batches: dict[str, list[dict[str, Any]]] = {}
        for record in records:
            key = target or "default"
            batches.setdefault(key, []).append({
                "record_id": record.record_id,
                "event_type": record.event_type.type_id,
                "parsed_fields": record.parsed_fields,
                "event_time": record.event_time.isoformat(),
            })
        return [
            {"target": k, "count": len(v), "payload": v}
            for k, v in batches.items()
        ]

    # ---------- 内部辅助方法 ----------

    def _classify_entry(self, entry: LogEntry,
                        rule: ParseRule | None = None
                        ) -> tuple[EventTypeDef, ClassificationBasis]:
        """根据解析字段对日志条目做事件分类，并留痕分类依据。"""
        return self._classify_fields(
            entry.parsed_fields or {},
            rule_id=rule.rule_id if rule else "",
        )

    def _classify_fields(self, fields: dict[str, str],
                         rule_id: str = "") -> tuple[EventTypeDef, ClassificationBasis]:
        level = str(fields.get("level", "")).upper()
        action = str(fields.get("action", "")).upper()
        if level == "ERROR":
            event_type = PRESET_EVENT_TYPES["error"]
        elif action in ("LOGIN", "LOGOUT", "AUTH", "AUTHENTICATE"):
            event_type = PRESET_EVENT_TYPES["auth"]
        else:
            event_type = PRESET_EVENT_TYPES["access"]
        basis = ClassificationBasis(
            level=level,
            action=action,
            rule_id=rule_id,
            type_id=event_type.type_id,
        )
        return event_type, basis

    def _active_claim(self, source_id: str) -> ReplayClaim | None:
        for claim in self._claims.values():
            if claim.source_id == source_id and claim.state == "已领用":
                return claim
        return None

    def _resolve_manifest(self, source_id: str,
                          manifest_id: str | None) -> ConfirmedManifest | None:
        if manifest_id is not None:
            manifest = self._manifests.get(manifest_id)
            if manifest is not None and manifest.source_id == source_id:
                return manifest
            return None
        ids = self._manifests_by_source.get(source_id, [])
        for mid in reversed(ids):
            manifest = self._manifests[mid]
            if manifest.state in ("已确认", "已交回"):
                return manifest
        return None

    def _append_audit(self, action: str, **payload: Any) -> None:
        self._audit.append({
            "action": action,
            "time": datetime.now().isoformat(),
            **payload,
        })

    # ---------- 查询视图 ----------

    def get_event_store(self) -> dict[str, list[EventRecord]]:
        return self._event_store

    def get_event_record(self, source_line_key: str) -> EventRecord | None:
        return self._event_index.get(source_line_key)

    def get_checkpoints(self) -> list[BatchCheckpoint]:
        return list(self._checkpoint_store.values())

    def get_manifest(self, manifest_id: str) -> ConfirmedManifest | None:
        return self._manifests.get(manifest_id)

    def list_manifests(self, source_id: str | None = None) -> list[ConfirmedManifest]:
        if source_id is None:
            return list(self._manifests.values())
        return [self._manifests[mid]
                for mid in self._manifests_by_source.get(source_id, [])]

    def get_claim(self, claim_id: str) -> ReplayClaim | None:
        return self._claims.get(claim_id)

    def get_progress(self, source_id: str) -> SourceProgress | None:
        return self._progress.get(source_id)

    def get_pending_source_lines(self, source_id: str) -> list[str]:
        """来源下已入库但尚未成功核销的源行——续采/补采的待处理清单。"""
        progress = self._progress.get(source_id)
        done = progress.replayed_line_keys if progress else set()
        return [
            key for key, event in self._event_index.items()
            if event.source_id == source_id and key not in done
        ]

    def get_audit_trail(self) -> list[dict[str, Any]]:
        return list(self._audit)


# ---------- 测试辅助工厂 ----------

def make_sample_raw_lines() -> list[str]:
    """生成用于确定测试的混合日志样本行（包含脏日志、格式不匹配的行）。"""
    return [
        # access 日志
        '192.168.1.10 - - [15/Nov/2026:14:30:05 +0800] "GET /api/users HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
        '10.0.0.55 - - [15/Nov/2026:14:30:06 +0800] "POST /api/events/ingest HTTP/1.1" 201 567 "-" "curl/7.88"',
        '172.16.0.3 - - [15/Nov/2026:14:30:07 +0800] "GET /api/health HTTP/1.1" 500 89 "-" "kube-probe/1.28"',
        # app 日志
        '2026-11-15 14:30:05.123 [http-nio-8080-exec-1] INFO  com.example.IngestController - 采集作业 INGE-0001 启动',
        '2026-11-15 14:30:05.456 [http-nio-8080-exec-2] ERROR com.example.ParserEngine - 解析失败：regex mismatch at line 88',
        '2026-11-15 14:30:05.789 [pool-3-thread-1] DEBUG com.example.CheckpointStore - 检查点 BATC-0001 写入成功',
        '2026-11-15 14:30:06.012 [http-nio-8080-exec-3] WARN  com.example.MaskService - 脱敏规则 MASK-0003 遗漏字段 user_email',
        # 脏日志（格式不匹配）
        '2026-11-15 14:30:06.234 orphan line without proper format',
        '',
        # app 日志 error（重复模式用于测试去重）
        '2026-11-15 14:30:06.456 [http-nio-8080-exec-2] ERROR com.example.ParserEngine - 解析失败：regex mismatch at line 89',
        # sys 日志
        'Nov 15 14:30:07 auth-server sshd[8891]: LOGIN user=admin from=10.0.0.100',
        'Nov 15 14:30:08 auth-server sshd[8892]: LOGIN user=operator from=192.168.1.50',
        'Nov 15 14:30:09 auth-server sshd[8893]: AUTH failure user=guest reason=password_expired',
        # access 日志（含敏感IP用于脱敏测试）
        '192.168.1.99 - - [15/Nov/2026:14:30:10 +0800] "GET /api/users/13800138000 HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
        # 脏行（纯数字）
        '2926-16-15 99:99:99.999 [bad] BAD  malformed - 完全不匹配任何格式',
        '~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~',
    ]


def make_pipeline() -> IngestPipeline:
    """工厂函数：创建一个预配置的采集管道实例。"""
    return IngestPipeline()
