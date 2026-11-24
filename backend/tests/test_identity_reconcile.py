"""测试：身份冲突修复与确认清单续采（classify_events → store_events 全链路）。

覆盖题面场景：
- 不同主机/来源的相同首行文本不会撞同一事件编号；断线补采幂等不重复写入；
- 确认批次生成事件清单，采集作业凭持久来源证据续采；
- 解析更正绑定旧原行内容与旧分类依据，位置未变但字节不符必须拒绝；
- 回放结果按清单逐行核销：A 成功 B 失败只结算 A，重送幂等，更正不抹掉失败；
- 重复提交同一源行只保留一份事件，另一来源/不同位置仍分别计数；
- 一轮回放只认一个完整确认的分类版本，已领用旧清单只能结案或交回；
- A 入库回执丢失、重试与 INFO→ERROR 更正并发时的回放资格与单次结算。
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:  # 兼容有/无 pytest 的运行环境
    import pytest
except ImportError:  # pragma: no cover
    import contextlib

    class _PytestShim:
        @staticmethod
        @contextlib.contextmanager
        def raises(exc_type):
            try:
                yield
            except exc_type:
                return
            raise AssertionError(f"预期抛出 {exc_type.__name__}，但未抛出")

    pytest = _PytestShim()

from app.core.models import (
    ClassificationBasis, IngestJob, LogSourceConfig, ParseCorrection,
    ParseResultStatus, ParseRule, ReplayResult,
)
from app.core.pipeline import (
    IngestPipeline, PRESET_PARSE_RULES, build_source_line_key,
    compute_raw_checksum, make_event_record_id,
)

APP_RULE = PRESET_PARSE_RULES[1]  # PARS-0002，app 日志正则

# A、B 两源首行文本恰好相同
SAME_LINE = (
    "2026-11-15 14:30:05.123 [http-nio-8080-exec-1] INFO  "
    "com.example.IngestController - 采集作业 INGE-0001 启动"
)
# 同一位置的解析更正：INFO → ERROR
CORRECTED_LINE = (
    "2026-11-15 14:30:05.123 [http-nio-8080-exec-1] ERROR "
    "com.example.IngestController - 采集作业 INGE-0001 启动"
)

SOURCE_A = LogSourceConfig(
    source_id="LOG_A", source_name="SourceA", app_label="app-a",
    log_path="/var/log/app/a.log", log_format="app",
)
SOURCE_B = LogSourceConfig(
    source_id="LOG_B", source_name="SourceB", app_label="app-b",
    log_path="/var/log/app/b.log", log_format="app",
)


def _ingest_first_line(pipeline: IngestPipeline,
                       source: LogSourceConfig,
                       line: str = SAME_LINE,
                       line_no: int = 1):
    """标准化单行：解析 → 采集作业 → 分类，返回 (entry, record)。"""
    entries = pipeline.parse_raw_lines(source, [line])
    parsed = pipeline.apply_parse_rules(entries, APP_RULE)
    assert parsed[0].parse_status == ParseResultStatus.OK
    job = IngestJob(job_id=f"INGE-{source.source_id}", source_id=source.source_id)
    pipeline.run_ingest_job(parsed, job)
    records = pipeline.classify_events(parsed, rule=APP_RULE)
    assert len(records) == 1
    return parsed[0], records[0]


def _info_basis() -> ClassificationBasis:
    return ClassificationBasis(level="INFO", action="",
                               rule_id="PARS-0002", type_id="EVEN-0001")


class TestSourceLineIdentity:
    """身份标准化：来源+行号决定身份，与主机名、文本内容无关。"""

    def test_same_text_different_sources_get_distinct_ids(self):
        pipeline = IngestPipeline()
        _, rec_a = _ingest_first_line(pipeline, SOURCE_A)
        _, rec_b = _ingest_first_line(pipeline, SOURCE_B)

        assert rec_a.source_line_key != rec_b.source_line_key
        assert rec_a.record_id != rec_b.record_id
        # 编号由来源身份确定性派生
        assert rec_a.record_id == make_event_record_id(
            build_source_line_key("LOG_A", 1))
        # 相同文本的原行校验值只在来源身份一致时才相同
        assert rec_a.raw_checksum != rec_b.raw_checksum
        assert rec_a.raw_checksum == compute_raw_checksum("LOG_A", 1, SAME_LINE)

    def test_same_source_same_position_stable_identity_across_retry(self):
        pipeline = IngestPipeline()
        _, rec_first = _ingest_first_line(pipeline, SOURCE_A)
        # 断线重采：同来源、同行号、同文本再次标准化
        _, rec_retry = _ingest_first_line(pipeline, SOURCE_A)
        assert rec_retry.source_line_key == rec_first.source_line_key
        assert rec_retry.record_id == rec_first.record_id

    def test_same_source_different_positions_count_separately(self):
        pipeline = IngestPipeline()
        entries = pipeline.parse_raw_lines(SOURCE_A, [SAME_LINE, SAME_LINE])
        parsed = pipeline.apply_parse_rules(entries, APP_RULE)
        records = pipeline.classify_events(parsed, rule=APP_RULE)
        keys = {r.source_line_key for r in records}
        ids = {r.record_id for r in records}
        assert len(keys) == 2 and len(ids) == 2


class TestIdempotentStore:
    """入库幂等：重采不重复写入，不同来源分别计数。"""

    def test_retry_does_not_duplicate_store_list(self):
        pipeline = IngestPipeline()
        _, rec_a = _ingest_first_line(pipeline, SOURCE_A)
        first = pipeline.store_events_detail([rec_a])
        assert first["stored"] == 1

        # 模拟 A 入库回执丢失后的断线重试：重新标准化并再次入库
        _, rec_a_retry = _ingest_first_line(pipeline, SOURCE_A)
        second = pipeline.store_events_detail([rec_a_retry])
        assert second["stored"] == 0
        assert second["duplicated"] == 1

        # 库存列表中 A 只有一条
        all_records = [r for rows in pipeline.get_event_store().values() for r in rows]
        a_records = [r for r in all_records if r.source_id == "LOG_A"]
        assert len(a_records) == 1
        # store_events 保持旧签名：返回新写入条数
        assert pipeline.store_events([rec_a_retry]) == 0

    def test_two_sources_identical_text_each_stored_once(self):
        pipeline = IngestPipeline()
        _, rec_a = _ingest_first_line(pipeline, SOURCE_A)
        _, rec_b = _ingest_first_line(pipeline, SOURCE_B)
        pipeline.store_events([rec_a, rec_b])

        all_records = [r for rows in pipeline.get_event_store().values() for r in rows]
        by_source = {r.source_id for r in all_records}
        assert by_source == {"LOG_A", "LOG_B"}
        assert len(all_records) == 2

    def test_persisted_progress_drives_resume_priority(self):
        """重新进入补采时，待处理清单以持久保存的来源证据为准。"""
        pipeline = IngestPipeline()
        _, rec_a = _ingest_first_line(pipeline, SOURCE_A)
        pipeline.store_events([rec_a])
        progress = pipeline.get_progress("LOG_A")
        assert progress is not None
        assert build_source_line_key("LOG_A", 1) in progress.processed_line_keys
        pending = pipeline.get_pending_source_lines("LOG_A")
        assert build_source_line_key("LOG_A", 1) in pending  # 尚未核销，仍待处理


class TestConfirmedManifestAndClaim:
    """确认批次清单与重放领用：一轮只认一个完整确认的分类版本。"""

    def test_confirm_batch_hands_manifest_to_job(self):
        pipeline = IngestPipeline()
        _, rec_a = _ingest_first_line(pipeline, SOURCE_A)
        pipeline.store_events([rec_a])
        manifest = pipeline.confirm_batch("LOG_A")

        assert len(manifest.events) == 1
        item = manifest.events[0]
        assert item.source_line_key == build_source_line_key("LOG_A", 1)
        assert item.record_id == rec_a.record_id
        assert rec_a.classification_version == manifest.classification_version

        job = IngestJob(job_id="INGE-LOG_A", source_id="LOG_A")
        resume = pipeline.resume_job_with_manifest(job)
        assert resume["resume"] is True
        assert resume["manifest_id"] == manifest.manifest_id
        assert len(resume["events"]) == 1

    def test_new_confirm_supersedes_unclaimed_manifest(self):
        pipeline = IngestPipeline()
        _, rec_a = _ingest_first_line(pipeline, SOURCE_A)
        pipeline.store_events([rec_a])
        first = pipeline.confirm_batch("LOG_A")
        second = pipeline.confirm_batch("LOG_A", [rec_a])
        assert first.state == "已作废"
        assert second.supersedes_version == first.classification_version
        # 同一来源不存在两份可用清单
        usable = [m for m in pipeline.list_manifests("LOG_A")
                  if m.state in ("已确认", "已领用")]
        assert len(usable) == 1

    def test_confirm_blocked_while_claim_active_until_close_or_release(self):
        pipeline = IngestPipeline()
        _, rec_a = _ingest_first_line(pipeline, SOURCE_A)
        pipeline.store_events([rec_a])
        pipeline.confirm_batch("LOG_A")
        claim = pipeline.claim_manifest("LOG_A")

        with pytest.raises(RuntimeError):
            pipeline.confirm_batch("LOG_A", [rec_a])

        # 明确交回后可以确认新版本
        pipeline.release_claim(claim.claim_id)
        new_manifest = pipeline.confirm_batch("LOG_A", [rec_a])
        assert new_manifest.state == "已确认"

    def test_closed_claim_keeps_single_settlement_version(self):
        pipeline = IngestPipeline()
        _, rec_a = _ingest_first_line(pipeline, SOURCE_A)
        pipeline.store_events([rec_a])
        manifest = pipeline.confirm_batch("LOG_A")
        claim = pipeline.claim_manifest("LOG_A")
        result = ReplayResult(
            source_line_key=build_source_line_key("LOG_A", 1),
            source_id="LOG_A", manifest_id=manifest.manifest_id, success=True,
        )
        pipeline.apply_replay_results([result])
        settled = pipeline.settle_replay(claim.claim_id)
        assert settled.state == "已结案"
        assert settled.settled_version == manifest.classification_version
        # 重复结算幂等，返回同一结案记录，完成数不变
        again = pipeline.settle_replay(claim.claim_id)
        assert again is settled
        progress = pipeline.get_progress("LOG_A")
        assert progress.replay_success_count == 1
        assert progress.settled_version == manifest.classification_version


class TestParseCorrection:
    """解析更正：绑定旧原行字节与旧分类依据。"""

    def _stored_event(self, pipeline: IngestPipeline):
        _, rec = _ingest_first_line(pipeline, SOURCE_A)
        pipeline.store_events([rec])
        return rec

    def test_correction_revises_only_its_own_event(self):
        pipeline = IngestPipeline()
        rec_a = self._stored_event(pipeline)
        _, rec_b = _ingest_first_line(pipeline, SOURCE_B)
        pipeline.store_events([rec_b])

        _, corrected_fields = APP_RULE.parse(CORRECTED_LINE)
        correction = ParseCorrection(
            source_id="LOG_A", source_line_no=1,
            expected_raw_line=SAME_LINE,
            expected_raw_checksum=rec_a.raw_checksum,
            expected_basis=_info_basis(),
            new_parsed_fields=corrected_fields,
            new_raw_line=CORRECTED_LINE,
        )
        updated = pipeline.apply_parse_correction(correction)
        assert updated.record_id == rec_a.record_id          # 身份不变
        assert updated.event_type.type_id == "EVEN-0002"     # INFO → ERROR
        assert updated.parsed_fields["level"] == "ERROR"
        assert updated.raw_checksum == compute_raw_checksum("LOG_A", 1, CORRECTED_LINE)
        # 另一来源的同文本事件不受影响，仍各计一条
        assert pipeline.get_event_record(build_source_line_key("LOG_B", 1)) is rec_b
        total = sum(len(rows) for rows in pipeline.get_event_store().values())
        assert total == 2

    def test_correction_rejected_when_raw_bytes_mismatch(self):
        pipeline = IngestPipeline()
        rec_a = self._stored_event(pipeline)
        _, fields = APP_RULE.parse(CORRECTED_LINE)
        tampered_line = SAME_LINE + " "  # 位置没变但原文字节不符
        correction = ParseCorrection(
            source_id="LOG_A", source_line_no=1,
            expected_raw_line=tampered_line,
            expected_raw_checksum=compute_raw_checksum("LOG_A", 1, tampered_line),
            expected_basis=_info_basis(),
            new_parsed_fields=fields,
            new_raw_line=CORRECTED_LINE,
        )
        with pytest.raises(ValueError):
            pipeline.apply_parse_correction(correction)
        # 事件保持原状
        untouched = pipeline.get_event_record(build_source_line_key("LOG_A", 1))
        assert untouched.original_content == rec_a.original_content
        assert untouched.event_type.type_id == "EVEN-0001"

    def test_correction_rejected_when_checksum_mismatch(self):
        pipeline = IngestPipeline()
        self._stored_event(pipeline)
        _, fields = APP_RULE.parse(CORRECTED_LINE)
        correction = ParseCorrection(
            source_id="LOG_A", source_line_no=1,
            expected_raw_line=SAME_LINE,
            expected_raw_checksum="deadbeef" * 8,
            expected_basis=_info_basis(),
            new_parsed_fields=fields,
        )
        with pytest.raises(ValueError):
            pipeline.apply_parse_correction(correction)

    def test_correction_rejected_when_basis_mismatch(self):
        pipeline = IngestPipeline()
        self._stored_event(pipeline)
        _, fields = APP_RULE.parse(CORRECTED_LINE)
        wrong_basis = ClassificationBasis(level="ERROR", action="",
                                          rule_id="PARS-0002", type_id="EVEN-0002")
        correction = ParseCorrection(
            source_id="LOG_A", source_line_no=1,
            expected_raw_line=SAME_LINE,
            expected_raw_checksum=compute_raw_checksum("LOG_A", 1, SAME_LINE),
            expected_basis=wrong_basis,
            new_parsed_fields=fields,
        )
        with pytest.raises(ValueError):
            pipeline.apply_parse_correction(correction)

    def test_correction_on_unknown_line_rejected(self):
        pipeline = IngestPipeline()
        correction = ParseCorrection(
            source_id="LOG_A", source_line_no=99,
            expected_raw_line=SAME_LINE,
            expected_raw_checksum=compute_raw_checksum("LOG_A", 99, SAME_LINE),
            expected_basis=_info_basis(),
            new_parsed_fields={"level": "ERROR"},
        )
        with pytest.raises(ValueError):
            pipeline.apply_parse_correction(correction)


class TestReplayReconciliation:
    """回放结果逐行核销：成功入账、失败留存、重送幂等。"""

    def _two_source_manifest(self, pipeline: IngestPipeline):
        _, rec_a = _ingest_first_line(pipeline, SOURCE_A)
        _, rec_b = _ingest_first_line(pipeline, SOURCE_B)
        pipeline.store_events([rec_a, rec_b])
        manifest_a = pipeline.confirm_batch("LOG_A", [rec_a])
        manifest_b = pipeline.confirm_batch("LOG_B", [rec_b])
        return manifest_a, manifest_b

    def test_success_and_failure_settle_independently(self):
        pipeline = IngestPipeline()
        manifest_a, manifest_b = self._two_source_manifest(pipeline)
        pipeline.claim_manifest("LOG_A")
        pipeline.claim_manifest("LOG_B")
        key_a = build_source_line_key("LOG_A", 1)
        key_b = build_source_line_key("LOG_B", 1)

        summary = pipeline.apply_replay_results([
            ReplayResult(source_line_key=key_a, source_id="LOG_A",
                         manifest_id=manifest_a.manifest_id, success=True),
            ReplayResult(source_line_key=key_b, source_id="LOG_B",
                         manifest_id=manifest_b.manifest_id, success=False,
                         detail="下游超时"),
        ])
        assert summary["succeeded"] == 1
        assert summary["failed"] == 1
        assert summary["pending_keys"] == [key_b]

        progress_a = pipeline.get_progress("LOG_A")
        progress_b = pipeline.get_progress("LOG_B")
        assert key_a in progress_a.replayed_line_keys
        assert progress_a.replay_success_count == 1
        assert key_b not in progress_b.replayed_line_keys
        assert key_b in progress_b.failed_line_keys
        assert progress_b.replay_success_count == 0

    def test_redelivered_result_is_idempotent(self):
        pipeline = IngestPipeline()
        manifest_a, _ = self._two_source_manifest(pipeline)
        pipeline.claim_manifest("LOG_A")
        key_a = build_source_line_key("LOG_A", 1)
        result = ReplayResult(source_line_key=key_a, source_id="LOG_A",
                              manifest_id=manifest_a.manifest_id, success=True)
        pipeline.apply_replay_results([result])
        again = pipeline.apply_replay_results([result])
        assert again["succeeded"] == 0
        assert again["duplicate_ignored"] == 1
        assert pipeline.get_progress("LOG_A").replay_success_count == 1

    def test_correction_does_not_erase_failure(self):
        pipeline = IngestPipeline()
        _, manifest_b = self._two_source_manifest(pipeline)
        pipeline.claim_manifest("LOG_B")
        key_b = build_source_line_key("LOG_B", 1)
        pipeline.apply_replay_results([
            ReplayResult(source_line_key=key_b, source_id="LOG_B",
                         manifest_id=manifest_b.manifest_id, success=False,
                         detail="下游超时"),
        ])
        # 随后 B 收到合法更正：失败记录必须保留
        rec_b = pipeline.get_event_record(key_b)
        _, fields = APP_RULE.parse(CORRECTED_LINE)
        pipeline.apply_parse_correction(ParseCorrection(
            source_id="LOG_B", source_line_no=1,
            expected_raw_line=SAME_LINE,
            expected_raw_checksum=rec_b.raw_checksum,
            expected_basis=_info_basis(),
            new_parsed_fields=fields, new_raw_line=CORRECTED_LINE,
        ))
        progress_b = pipeline.get_progress("LOG_B")
        assert key_b in progress_b.failed_line_keys
        assert key_b not in progress_b.replayed_line_keys
        assert progress_b.replay_success_count == 0

    def test_results_not_in_manifest_are_invalid(self):
        pipeline = IngestPipeline()
        manifest_a, _ = self._two_source_manifest(pipeline)
        pipeline.claim_manifest("LOG_A")
        summary = pipeline.apply_replay_results([
            ReplayResult(source_line_key="LOG_A#L999", source_id="LOG_A",
                         manifest_id=manifest_a.manifest_id, success=True),
        ])
        assert summary["invalid"] == 1
        assert summary["succeeded"] == 0

    def test_stale_manifest_cannot_settle_corrected_event(self):
        """事件被更正后，旧分类版本清单的回放结果必须拒绝，且不计入来源进度。"""
        pipeline = IngestPipeline()
        manifest_a, _ = self._two_source_manifest(pipeline)
        pipeline.claim_manifest("LOG_A")
        key_a = build_source_line_key("LOG_A", 1)
        rec_a = pipeline.get_event_record(key_a)
        _, fields = APP_RULE.parse(CORRECTED_LINE)
        pipeline.apply_parse_correction(ParseCorrection(
            source_id="LOG_A", source_line_no=1,
            expected_raw_line=SAME_LINE,
            expected_raw_checksum=rec_a.raw_checksum,
            expected_basis=_info_basis(),
            new_parsed_fields=fields, new_raw_line=CORRECTED_LINE,
        ))
        summary = pipeline.apply_replay_results([
            ReplayResult(source_line_key=key_a, source_id="LOG_A",
                         manifest_id=manifest_a.manifest_id, success=True),
        ])
        assert summary["invalid"] == 1
        assert summary["succeeded"] == 0
        progress = pipeline.get_progress("LOG_A")
        assert key_a not in progress.replayed_line_keys
        assert progress.replay_success_count == 0


class TestEndToEndLostReceiptAndConcurrentCorrection:
    """题面端到端：A 回执丢失 + 重试与更正并发 + 领用中回放资格切换。"""

    def test_full_scenario(self):
        pipeline = IngestPipeline()

        # 1) A、B 各发一条相同文本并入库
        _, rec_a = _ingest_first_line(pipeline, SOURCE_A)
        _, rec_b = _ingest_first_line(pipeline, SOURCE_B)
        pipeline.store_events([rec_a, rec_b])

        # 2) 丢掉 A 的入库回执：采集端断线重试，同批还带着 INFO→ERROR 更正
        _, rec_a_retry = _ingest_first_line(pipeline, SOURCE_A)
        retry_summary = pipeline.store_events_detail([rec_a_retry])
        assert retry_summary["stored"] == 0          # 重试不重复写入
        assert retry_summary["duplicated"] == 1

        # 3) 库存中 A、B 各一条
        all_records = [r for rows in pipeline.get_event_store().values() for r in rows]
        assert len(all_records) == 2
        counts = {}
        for r in all_records:
            counts[r.source_id] = counts.get(r.source_id, 0) + 1
        assert counts == {"LOG_A": 1, "LOG_B": 1}

        # 4) 确认两源清单并领用 A 的回放清单（值班人员已开始回放）
        manifest_a = pipeline.confirm_batch("LOG_A", [rec_a])
        pipeline.confirm_batch("LOG_B", [rec_b])
        claim_a = pipeline.claim_manifest("LOG_A")
        key_a = build_source_line_key("LOG_A", 1)
        eligibility_before = pipeline.get_replay_eligibility("LOG_A", key_a)
        assert eligibility_before["eligible"] is True
        assert eligibility_before["version"] == manifest_a.classification_version

        # 5) 原提交与更正并发完成：合法更正落到 A 的唯一事件上
        _, corrected_fields = APP_RULE.parse(CORRECTED_LINE)
        updated = pipeline.apply_parse_correction(ParseCorrection(
            source_id="LOG_A", source_line_no=1,
            expected_raw_line=SAME_LINE,
            expected_raw_checksum=rec_a.raw_checksum,
            expected_basis=_info_basis(),
            new_parsed_fields=corrected_fields,
            new_raw_line=CORRECTED_LINE,
        ))
        assert updated.record_id == rec_a.record_id
        assert updated.event_type.type_id == "EVEN-0002"

        # 6) 原回放资格失效：版本漂移，需要重新领取
        eligibility_after = pipeline.get_replay_eligibility("LOG_A", key_a)
        assert eligibility_after["eligible"] is False
        assert eligibility_after["need_reclaim"] is True
        assert eligibility_after["claimed_version"] == manifest_a.classification_version
        assert eligibility_after["current_version"] == updated.classification_version

        # 7) 已领用旧清单不能拖着两份清单继续：先交回，再按新版本确认并重新领用
        pipeline.release_claim(claim_a.claim_id)
        manifest_a_v2 = pipeline.confirm_batch("LOG_A", [updated])
        assert manifest_a.state == "已交回"
        new_claim = pipeline.claim_manifest("LOG_A", manifest_a_v2.manifest_id)
        assert new_claim.classification_version == manifest_a_v2.classification_version
        eligibility_reclaimed = pipeline.get_replay_eligibility("LOG_A", key_a)
        assert eligibility_reclaimed["eligible"] is True

        # 8) 按新清单回放 A 成功并结算；任何时点只结算一次，可回查结算版本
        summary = pipeline.apply_replay_results([
            ReplayResult(source_line_key=key_a, source_id="LOG_A",
                         manifest_id=manifest_a_v2.manifest_id, success=True),
        ])
        assert summary["succeeded"] == 1
        settled = pipeline.settle_replay(new_claim.claim_id)
        assert settled.settled_version == manifest_a_v2.classification_version
        progress_a = pipeline.get_progress("LOG_A")
        assert progress_a.settled_claim_id == new_claim.claim_id
        assert progress_a.replay_success_count == 1
        with pytest.raises(RuntimeError):
            # 另一个认领无法对同一来源二次结算
            pipeline.settle_replay(claim_a.claim_id)

        # 9) 作业续采视图反映新版本与已核销进度
        job = IngestJob(job_id="INGE-LOG_A", source_id="LOG_A")
        resume = pipeline.resume_job_with_manifest(job)
        assert resume["classification_version"] == manifest_a_v2.classification_version
        assert resume["replayed_count"] == 1
        assert resume["pending_keys"] == []

        # 10) 审计轨迹可回查关键动作
        actions = {row["action"] for row in pipeline.get_audit_trail()}
        assert {
            "store_events", "store_duplicate_skipped", "confirm_batch",
            "claim_manifest", "release_claim", "parse_correction_applied",
            "replay_settled", "settle_replay",
        }.issubset(actions)


# ---------- 运行入口（确定性测试，不依赖 pytest 也可直接运行） ----------

if __name__ == "__main__":
    import traceback

    test_classes = [
        TestSourceLineIdentity, TestIdempotentStore, TestConfirmedManifestAndClaim,
        TestParseCorrection, TestReplayReconciliation,
        TestEndToEndLostReceiptAndConcurrentCorrection,
    ]
    passed = failed = 0
    for cls in test_classes:
        for name in sorted(dir(cls)):
            if not name.startswith("test_"):
                continue
            try:
                getattr(cls(), name)()
                passed += 1
                print(f"  PASS  test_identity_reconcile: {cls.__name__}.{name}")
            except Exception:
                failed += 1
                print(f"  FAIL  test_identity_reconcile: {cls.__name__}.{name}")
                traceback.print_exc()
    print(f"\ntest_identity_reconcile: {passed} passed, {failed} failed, "
          f"{passed + failed} total")
    sys.exit(1 if failed else 0)
