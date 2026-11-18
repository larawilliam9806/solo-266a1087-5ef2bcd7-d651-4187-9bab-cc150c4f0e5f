"""SQLite 登记 + 下游目录原子发布 + 发布凭据链 + 启动一致性恢复。

设计要点
--------
* SQLite 是版本/行数/凭据登记的唯一真相源；下游目录中的 CSV 与凭据只是镜像。
* 发布在单个 ``BEGIN IMMEDIATE`` 事务内完成：先写版本快照并 fsync，
  再 ``os.replace`` 原子改名下游 CSV 与凭据（下游只会看到完整文件），
  最后提交事务登记新版本；任一步失败都会把下游文件恢复为旧登记内容。
* 提交前崩溃：重启时按数据库登记重新生成/核对 CSV 与凭据，
  并清理遗留临时文件；登记里不存在的游离文件会被移入 quarantine 隔离。
* 凭据链：每版凭据记录 CSV 的 SHA-256 与前一版凭据文件摘要；链首版无前驱。
  取证启用前的旧版只按登记结果重建展示，绝不补造凭据。
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

from .evidence import build_credential, sha256_hex
from .validation import format_concentration, render_csv

LIVE_FILENAME = "published_results.csv"
CREDENTIAL_FILENAME = "published_results.credential.json"


class PublishConflictError(Exception):
    """确认发布时基线版本已过期，需要重新预览。"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Storage:
    def __init__(self, data_dir: str, downstream_dir: str):
        self.data_dir = os.path.abspath(data_dir)
        self.downstream_dir = os.path.abspath(downstream_dir)
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(self.downstream_dir, exist_ok=True)
        self.db_path = os.path.join(self.data_dir, "wq_publish.db")
        self.live_path = os.path.join(self.downstream_dir, LIVE_FILENAME)
        self.credential_path = os.path.join(self.downstream_dir, CREDENTIAL_FILENAME)
        self.quarantine_dir = os.path.join(self.data_dir, "quarantine")
        os.makedirs(self.quarantine_dir, exist_ok=True)
        self._init_db()
        self.recover()

    # ---------- 基础 ----------
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=15000")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS registry (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    current_version INTEGER NOT NULL,
                    batch_no TEXT NOT NULL,
                    row_count INTEGER NOT NULL,
                    published_at TEXT NOT NULL,
                    content_hash TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version INTEGER NOT NULL,
                    batch_no TEXT NOT NULL,
                    sample_no TEXT NOT NULL,
                    analyte TEXT NOT NULL,
                    concentration REAL NOT NULL CHECK (concentration >= 0),
                    UNIQUE (version, sample_no, analyte)
                );
                CREATE INDEX IF NOT EXISTS idx_results_version
                    ON results(version);
                CREATE TABLE IF NOT EXISTS revision_sessions (
                    token TEXT PRIMARY KEY,
                    batch_no TEXT NOT NULL,
                    base_version INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('pending','published','obsolete','cancelled'))
                );
                CREATE TABLE IF NOT EXISTS event_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    detail TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS published_versions (
                    version INTEGER PRIMARY KEY,
                    batch_no TEXT NOT NULL,
                    row_count INTEGER NOT NULL,
                    published_at TEXT NOT NULL,
                    csv_sha256 TEXT NOT NULL,
                    csv_content TEXT NOT NULL,
                    credential_text TEXT NOT NULL,
                    credential_sha256 TEXT NOT NULL,
                    prev_credential_sha256 TEXT,
                    evidence_from_version INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS evidence_activation (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    version INTEGER NOT NULL
                );
                """
            )

    def _log(self, conn: sqlite3.Connection, kind: str, detail: str) -> None:
        conn.execute(
            "INSERT INTO event_log(ts, kind, detail) VALUES (?,?,?)",
            (_now(), kind, detail),
        )

    def log(self, kind: str, detail: str) -> None:
        with self._connect() as conn:
            self._log(conn, kind, detail)

    # ---------- 启动恢复 ----------
    def _evidence_state(self, conn, reg):
        """返回 (启用版本, 当前版本是否应持有凭据)。"""
        row = conn.execute(
            "SELECT version FROM evidence_activation WHERE id = 1"
        ).fetchone()
        if row is None:
            # 首次运行本版本：从下一个新发布起启用凭据。
            # 已有的当前版本（如 v4）一律标记为无凭据，绝不补造。
            start = (reg["current_version"] + 1) if reg else 1
            conn.execute(
                "INSERT OR IGNORE INTO evidence_activation(id, version) VALUES (1, ?)",
                (start,),
            )
            self._log(
                conn, "recover",
                f"取证登记启用：自 v{start} 起为每版生成发布凭据；"
                "此前的版本标记为无凭据（不补造）",
            )
            row = {"version": start}
        active_from = row["version"]
        if reg is None:
            return active_from, False
        return active_from, reg["current_version"] >= active_from

    def recover(self) -> list[str]:
        """重启后核对下游文件与登记的一致性，返回本次恢复动作说明。"""
        actions: list[str] = []
        with self._connect() as conn:
            # 与 publish() 的写事务互斥：恢复期间不允许另一进程正在更换文件，
            # 也避免两个进程同时执行恢复动作。
            conn.execute("BEGIN IMMEDIATE")
            reg = conn.execute("SELECT * FROM registry WHERE id = 1").fetchone()
            active_from, evidence_active = self._evidence_state(conn, reg)

            # 1) 清理崩溃遗留的临时文件（可能只写了一半，绝不能被下游读到）
            for name in os.listdir(self.downstream_dir):
                if name.startswith((".tmp-publish-", ".tmp-credential-")):
                    path = os.path.join(self.downstream_dir, name)
                    try:
                        os.unlink(path)
                    except OSError:
                        pass
                    msg = f"清理遗留临时文件 downstream/{name}"
                    actions.append(msg)
                    self._log(conn, "recover", msg)
            self._clean_version_tmp()

            # 2) 登记为空：正式文件（若存在）属于无登记游离文件，隔离并保留
            if reg is None:
                for name in (LIVE_FILENAME, CREDENTIAL_FILENAME):
                    if os.path.exists(os.path.join(self.downstream_dir, name)):
                        dest = self._quarantine(name)
                        msg = (
                            f"数据库无任何发布登记，将下游游离文件 {name} "
                            f"移入 {os.path.basename(dest)}"
                        )
                        actions.append(msg)
                        self._log(conn, "recover", msg)
                return actions

            # 3) 文件缺失/哈希不符：以登记为准原子重建
            pv = conn.execute(
                "SELECT * FROM published_versions WHERE version = ?",
                (reg["current_version"],),
            ).fetchone()
            if evidence_active and pv is not None:
                expected_csv = pv["csv_content"]
                expected_hash = pv["csv_sha256"]
            else:
                # 启用前的旧版：只以 results 渲染，且不得有凭据（不补造证明）
                expected_csv = self._render_version(conn, reg["current_version"])
                expected_hash = hashlib.sha256(
                    expected_csv.encode("utf-8")
                ).hexdigest()

            need_rewrite = True
            if os.path.exists(self.live_path):
                with open(self.live_path, "rb") as fh:
                    actual_hash = hashlib.sha256(fh.read()).hexdigest()
                need_rewrite = actual_hash != expected_hash

            if need_rewrite:
                self._atomic_write(expected_csv)
                msg = (
                    f"下游 CSV 与登记 v{reg['current_version']} 不一致，"
                    "已按数据库登记重建（恢复为完整新版本）"
                )
                actions.append(msg)
                self._log(conn, "recover", msg)
            else:
                self._log(
                    conn,
                    "recover",
                    f"启动核对通过：下游 CSV 与登记 v{reg['current_version']} 一致",
                )

            # 4) 凭据文件：启用后的版本缺失/损坏则按登记重建；
            #    启用前的旧版若出现凭据，一律隔离，绝不指向不存在的数据。
            cred_path = self.credential_path
            if evidence_active and pv is not None:
                need_cred = True
                if os.path.exists(cred_path):
                    with open(cred_path, "rb") as fh:
                        need_cred = (
                            hashlib.sha256(fh.read()).hexdigest()
                            != pv["credential_sha256"]
                        )
                if need_cred:
                    self._atomic_write_bytes(
                        cred_path, pv["credential_text"].encode("utf-8"),
                        ".tmp-credential-",
                    )
                    msg = (
                        f"下游凭据与登记 v{reg['current_version']} 不一致，"
                        "已按数据库登记重建"
                    )
                    actions.append(msg)
                    self._log(conn, "recover", msg)
            elif os.path.exists(cred_path):
                dest = self._quarantine(CREDENTIAL_FILENAME)
                msg = (
                    f"当前 v{reg['current_version']} 属于取证启用前版本（启用于 "
                    f"v{active_from}），不应存在凭据；已移入 {os.path.basename(dest)}"
                )
                actions.append(msg)
                self._log(conn, "recover", msg)

            # 5) 同目录下游文件白名单：非登记文件一律隔离
            for name in os.listdir(self.downstream_dir):
                full = os.path.join(self.downstream_dir, name)
                if os.path.isfile(full) and name not in (
                    LIVE_FILENAME, CREDENTIAL_FILENAME
                ):
                    dest = self._quarantine(name)
                    msg = f"下游目录存在未登记文件 {name}，已移入 {os.path.basename(dest)}"
                    actions.append(msg)
                    self._log(conn, "recover", msg)

            # 5b) 历史快照：已登记的版本快照缺失/被篡改则按登记重建；
            #     未登记的快照目录（崩溃遗留）移入 quarantine，不冒充历史版本。
            known = {
                r["version"]: r for r in conn.execute(
                    "SELECT version, csv_content, csv_sha256, credential_text,"
                    " credential_sha256 FROM published_versions"
                ).fetchall()
            }
            versions_root = os.path.join(self.data_dir, "versions")
            os.makedirs(versions_root, exist_ok=True)
            for name in sorted(os.listdir(versions_root)):
                full = os.path.join(versions_root, name)
                if not os.path.isdir(full):
                    continue
                if not name.startswith("v") or not name[1:].isdigit() \
                        or int(name[1:]) not in known:
                    dest = self._quarantine_version(name)
                    msg = f"版本快照目录 {name} 无登记，已移入 {os.path.basename(dest)}"
                    actions.append(msg)
                    self._log(conn, "recover", msg)
                    continue
                pv = known[int(name[1:])]
                if not self._file_matches(
                    os.path.join(full, "published_results.csv"),
                    pv["csv_content"].encode("utf-8"),
                ):
                    self._atomic_write_in(
                        full, "published_results.csv", pv["csv_content"].encode("utf-8")
                    )
                    msg = f"版本快照 {name} 的 CSV 与登记不符，已按登记重建"
                    actions.append(msg)
                    self._log(conn, "recover", msg)
                if not self._file_matches(
                    os.path.join(full, CREDENTIAL_FILENAME),
                    pv["credential_text"].encode("utf-8"),
                ):
                    self._atomic_write_in(
                        full, CREDENTIAL_FILENAME, pv["credential_text"].encode("utf-8")
                    )
                    msg = f"版本快照 {name} 的凭据与登记不符，已按登记重建"
                    actions.append(msg)
                    self._log(conn, "recover", msg)

            # 6) 超过 24 小时仍未确认的预览会话作废，避免无限期堆积
            cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(
                timespec="seconds"
            )
            stale = conn.execute(
                "SELECT token FROM revision_sessions "
                "WHERE status='pending' AND created_at < ?",
                (cutoff,),
            ).fetchall()
            for s in stale:
                conn.execute(
                    "UPDATE revision_sessions SET status='obsolete' WHERE token=?",
                    (s["token"],),
                )
                self._log(
                    conn, "recover",
                    f"预览会话 {s['token'][:8]} 超过 24 小时未确认，已作废",
                )
        return actions

    def _quarantine(self, name: str) -> str:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        dest = os.path.join(self.quarantine_dir, f"{stamp}-{name}")
        os.replace(os.path.join(self.downstream_dir, name), dest)
        return dest

    def _quarantine_version(self, name: str) -> str:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        dest = os.path.join(self.quarantine_dir, f"{stamp}-version-{name}")
        os.replace(os.path.join(self.data_dir, "versions", name), dest)
        return dest

    def _clean_version_tmp(self) -> None:
        versions_root = os.path.join(self.data_dir, "versions")
        if not os.path.isdir(versions_root):
            return
        for root, _dirs, files in os.walk(versions_root):
            for name in files:
                if name.startswith(".tmp-"):
                    try:
                        os.unlink(os.path.join(root, name))
                    except OSError:
                        pass

    @staticmethod
    def _file_matches(path: str, expected: bytes) -> bool:
        try:
            with open(path, "rb") as fh:
                return fh.read() == expected
        except OSError:
            return False

    def _atomic_write(self, csv_text: str) -> None:
        """同目录临时文件 + fsync + 原子改名，保证下游只看到完整文件。"""
        self._atomic_write_bytes(
            self.live_path, csv_text.encode("utf-8"), ".tmp-publish-"
        )

    def _atomic_write_bytes(self, dest_path: str, data: bytes, prefix: str) -> None:
        tmp_path = os.path.join(
            self.downstream_dir, f"{prefix}{uuid.uuid4().hex}.tmp"
        )
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, dest_path)
            self._fsync_dir(self.downstream_dir)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    @staticmethod
    def _fsync_dir(path: str) -> None:
        try:
            fd = os.open(path, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _atomic_write_in(self, dest_dir: str, filename: str, data: bytes) -> None:
        """在任意目录内原子写入（用于历史版本快照，持久化后才提交事务）。"""
        os.makedirs(dest_dir, exist_ok=True)
        tmp_path = os.path.join(dest_dir, f".tmp-{uuid.uuid4().hex}.part")
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, os.path.join(dest_dir, filename))
            self._fsync_dir(dest_dir)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    # ---------- 读 ----------
    def current_registry(self):
        with self._connect() as conn:
            return conn.execute("SELECT * FROM registry WHERE id = 1").fetchone()

    def current_rows(self) -> list[dict]:
        with self._connect() as conn:
            reg = conn.execute("SELECT * FROM registry WHERE id = 1").fetchone()
            if reg is None:
                return []
            return self._version_rows(conn, reg["current_version"])

    def _version_rows(self, conn: sqlite3.Connection, version: int) -> list[dict]:
        cur = conn.execute(
            "SELECT sample_no, analyte, concentration FROM results "
            "WHERE version = ? ORDER BY sample_no, analyte",
            (version,),
        )
        return [dict(r) for r in cur.fetchall()]

    def _render_version(self, conn: sqlite3.Connection, version: int) -> str:
        return render_csv(self._version_rows(conn, version))

    def recent_events(self, limit: int = 20):
        with self._connect() as conn:
            return conn.execute(
                "SELECT * FROM event_log ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()

    def evidence_activation_version(self) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT version FROM evidence_activation WHERE id = 1"
            ).fetchone()
            return row["version"] if row else 1

    def published_version(self, version: int):
        """完整读取某一版（CSV 正文与凭据正文均来自数据库登记）。"""
        with self._connect() as conn:
            return conn.execute(
                "SELECT * FROM published_versions WHERE version = ?", (version,)
            ).fetchone()

    def all_version_numbers(self) -> list[int]:
        with self._connect() as conn:
            return [
                r["version"] for r in conn.execute(
                    "SELECT version FROM published_versions ORDER BY version"
                ).fetchall()
            ]

    def version_csv_text(self, version: int) -> str | None:
        """按版本取 CSV 正文：有凭据的版本取发布时快照，旧版按登记结果重建。"""
        with self._connect() as conn:
            pv = conn.execute(
                "SELECT csv_content FROM published_versions WHERE version = ?",
                (version,),
            ).fetchone()
            if pv is not None:
                return pv["csv_content"]
            exists = conn.execute(
                "SELECT 1 FROM results WHERE version = ? LIMIT 1", (version,)
            ).fetchone()
            if exists is None:
                return None
            return self._render_version(conn, version)

    def full_history(self) -> list[dict]:
        """全部版本（含取证启用前的旧版），按版本升序。

        旧版只按 results 重建展示信息，``has_credential`` 为 False，
        绝不生成凭据；``published_at`` 在旧数据中无法还原时为 None。
        """
        active_from = self.evidence_activation_version()
        with self._connect() as conn:
            evidence = {
                r["version"]: dict(r)
                for r in conn.execute(
                    "SELECT version, batch_no, row_count, published_at, csv_sha256,"
                    " credential_sha256, prev_credential_sha256, evidence_from_version"
                    " FROM published_versions ORDER BY version"
                ).fetchall()
            }
            legacy_versions = [
                r["version"] for r in conn.execute(
                    "SELECT DISTINCT version FROM results ORDER BY version"
                ).fetchall()
                if r["version"] not in evidence
            ]
            out: list[dict] = []
            for v in legacy_versions:
                meta = conn.execute(
                    "SELECT batch_no, COUNT(*) AS n FROM results"
                    " WHERE version = ? GROUP BY batch_no",
                    (v,),
                ).fetchone()
                csv_text = self._render_version(conn, v)
                out.append(
                    {
                        "version": v,
                        "batch_no": meta["batch_no"],
                        "row_count": meta["n"],
                        "published_at": None,
                        "csv_sha256": sha256_hex(csv_text),
                        "credential_sha256": None,
                        "prev_credential_sha256": None,
                        "evidence_from_version": active_from,
                        "has_credential": False,
                        "reconstructed": True,
                    }
                )
            for v, row in evidence.items():
                row["has_credential"] = True
                row["reconstructed"] = False
                out.append(row)
            out.sort(key=lambda d: d["version"])
            return out

    def version_credential(self, version: int):
        """返回 (payload dict 或 None, 凭据原始字节或 None, 凭据文件摘要或 None)。"""
        with self._connect() as conn:
            pv = conn.execute(
                "SELECT credential_text, credential_sha256 FROM published_versions"
                " WHERE version = ?",
                (version,),
            ).fetchone()
        if pv is None:
            return None, None, None
        raw = pv["credential_text"].encode("utf-8")
        return json.loads(pv["credential_text"]), raw, pv["credential_sha256"]

    def verify_uploaded_evidence(
        self, csv_raw: bytes | None, credential_raw: bytes | None
    ) -> dict:
        """核验另存的两份文件，只读、不改任何状态。

        所有判断只依据本次传入的字节和发布时已登记的记录；核验期间发生的
        新发布不会进入本次结论。
        """
        from .evidence import parse_credential, sha256_hex

        result = {
            "checks": [],
            "csv_payload": None,
            "credential_payload": None,
            "resolved_version": None,
            "csv_version": None,
            "credential_version": None,
            "ok": False,
            "reasons": [],
        }

        def add(name: str, ok: bool, detail: str) -> bool:
            result["checks"].append({"name": name, "ok": ok, "detail": detail})
            if not ok:
                result["reasons"].append(f"{name}：{detail}")
            return ok

        if csv_raw is None and credential_raw is None:
            add("输入", False, "请至少上传一份文件")
            return result

        payload = None
        if credential_raw is not None:
            payload, perrs = parse_credential(credential_raw)
            result["credential_payload"] = payload
            if perrs:
                for e in perrs:
                    add("凭据格式", False, e)
                return result
            add("凭据格式", True, "凭据 JSON 结构合法")

        csv_sum = sha256_hex(csv_raw) if csv_raw is not None else None
        cred_sum = sha256_hex(credential_raw) if credential_raw is not None else None

        with self._connect() as conn:
            # 单次读事务：整次核验看到同一份登记快照，
            # 期间发生的发布既不会混入，也不会改变本次结论。
            conn.execute("BEGIN")
            by_csv = None
            if csv_sum is not None:
                by_csv = conn.execute(
                    "SELECT version FROM published_versions WHERE csv_sha256 = ?",
                    (csv_sum,),
                ).fetchone()
            by_cred = None
            if cred_sum is not None:
                by_cred = conn.execute(
                    "SELECT version FROM published_versions"
                    " WHERE credential_sha256 = ?",
                    (cred_sum,),
                ).fetchone()
            legacy_versions = [
                r["version"] for r in conn.execute(
                    "SELECT DISTINCT version FROM results WHERE version NOT IN"
                    " (SELECT version FROM published_versions) ORDER BY version"
                ).fetchall()
            ]
            legacy_csv_match = None
            if csv_raw is not None:
                for v in legacy_versions:
                    if sha256_hex(self._render_version(conn, v)) == csv_sum:
                        legacy_csv_match = v
                        break
            chain = {
                r["version"]: dict(r) for r in conn.execute(
                    "SELECT version, batch_no, row_count, csv_sha256,"
                    " credential_sha256, prev_credential_sha256 FROM published_versions"
                ).fetchall()
            }

        if csv_raw is not None:
            if by_csv is not None:
                result["csv_version"] = by_csv["version"]
                add(
                    "CSV 摘要", True,
                    f"CSV 的 SHA-256 {csv_sum} 与登记 v{by_csv['version']} 一致",
                )
            elif legacy_csv_match is not None:
                result["csv_version"] = legacy_csv_match
                add(
                    "CSV 摘要", True,
                    f"CSV 与取证启用前旧版 v{legacy_csv_match} 的登记结果重建内容一致"
                    "（该旧版无凭据，不能据此证明发布链条）",
                )
            else:
                add("CSV 摘要", False, f"CSV 的 SHA-256 {csv_sum} 不在任何登记版本中")
        if credential_raw is not None:
            if by_cred is not None:
                result["credential_version"] = by_cred["version"]
                add(
                    "凭据摘要", True,
                    f"凭据文件摘要 {cred_sum} 与登记 v{by_cred['version']} 的凭据一致",
                )
            else:
                add(
                    "凭据摘要", False,
                    f"凭据文件摘要 {cred_sum} 不是本系统登记的任何凭据"
                    "（文件可能被改动、重新格式化或并非本系统生成）",
                )

        if payload is not None:
            v = payload["version"]
            reg = chain.get(v)
            if reg is None:
                result["resolved_version"] = None
                add(
                    "凭据版本", False,
                    f"凭据声明 v{v}，但登记中没有该版本的凭据记录"
                    + (
                        "（该版本属取证启用前旧版，按规则无凭据、不补造）"
                        if v in legacy_versions else "（可能来自另一套数据）"
                    ),
                )
            else:
                result["resolved_version"] = v
                add(
                    "凭据批次号", payload["batch_no"] == reg["batch_no"],
                    f"凭据批次号 {payload['batch_no']}，登记批次号 {reg['batch_no']}",
                )
                add(
                    "凭据 CSV 摘要", payload["csv_sha256"] == reg["csv_sha256"],
                    f"凭据记录 CSV 摘要 {payload['csv_sha256']}，"
                    f"登记为 {reg['csv_sha256']}",
                )
                if payload.get("row_count") is not None:
                    add(
                        "凭据行数", payload["row_count"] == reg["row_count"],
                        f"凭据行数 {payload['row_count']}，登记行数 {reg['row_count']}",
                    )
                expected_prev = reg["prev_credential_sha256"]
                actual_prev = payload["prev_credential_sha256"]
                if expected_prev is None:
                    add(
                        "前版凭据", actual_prev is None,
                        "该版本为取证链首版，凭据应声明无前驱"
                        if actual_prev is None
                        else f"凭据声明前驱 {actual_prev}，但登记中该版为链首（无前驱）",
                    )
                else:
                    add(
                        "前版凭据", actual_prev == expected_prev,
                        f"凭据前驱 {actual_prev}，登记 v{v-1} 的凭据摘要为 "
                        f"{expected_prev}"
                        if actual_prev == expected_prev else
                        f"凭据声明前驱 {actual_prev}，但登记 v{v-1} 的凭据摘要为 "
                        f"{expected_prev}（链条不接续：可能接错版本或前版文件被替换）",
                    )
                    prev_reg = chain.get(v - 1)
                    add(
                        "前一版凭据存在", prev_reg is not None
                        and prev_reg["credential_sha256"] == expected_prev,
                        f"登记 v{v-1} 的凭据摘要 {expected_prev} 存在"
                        if prev_reg is not None else
                        f"登记中没有 v{v-1} 的凭据记录，链条无法接续",
                    )

        if csv_raw is not None and payload is not None:
            add(
                "CSV 与凭据配对", payload["csv_sha256"] == csv_sum,
                f"凭据声明的 CSV 摘要 {payload['csv_sha256']}，"
                f"上传 CSV 的实际摘要 {csv_sum}",
            )

        if csv_raw is None:
            add("CSV 文件", False, "仅上传了凭据：无法核对 CSV 内容本身")
        if credential_raw is None:
            add("凭据文件", False, "仅上传了 CSV：无法核对链条与凭据本身")

        result["ok"] = bool(result["checks"]) and all(
            c["ok"] for c in result["checks"]
        )
        return result

    def verify_registered_version(self, version: int) -> dict:
        """核验选定版本自身的登记内凭据（只读、不改状态）。

        取该版本的发布快照（CSV 正文、凭据正文）与登记摘要逐项比对，并检查
        与前一版的链接。结论只依赖本次读取的该版本记录，期间发生的其他发布
        不会改变它。
        """
        from .evidence import parse_credential, sha256_hex

        checks = []

        def add(name: str, ok: bool, detail: str) -> bool:
            checks.append({"name": name, "ok": ok, "detail": detail})
            return ok

        with self._connect() as conn:
            pv = conn.execute(
                "SELECT * FROM published_versions WHERE version = ?", (version,)
            ).fetchone()
            prev = None
            if pv is not None and pv["prev_credential_sha256"] is not None:
                prev = conn.execute(
                    "SELECT version, credential_sha256 FROM published_versions"
                    " WHERE credential_sha256 = ?",
                    (pv["prev_credential_sha256"],),
                ).fetchone()
            first = (
                conn.execute(
                    "SELECT version FROM published_versions ORDER BY version LIMIT 1"
                ).fetchone()
            )

        if pv is None:
            return {
                "version": version,
                "checks": [{
                    "name": "版本",
                    "ok": False,
                    "detail": f"v{version} 没有发布凭据（取证启用前的版本不补造）",
                }],
                "ok": False, "reasons": ["该版本无凭据"],
            }

        csv_raw = pv["csv_content"].encode("utf-8")
        cred_raw = pv["credential_text"].encode("utf-8")
        add(
            "CSV 内容", sha256_hex(csv_raw) == pv["csv_sha256"],
            f"快照 CSV 实际摘要 {sha256_hex(csv_raw)}，登记 {pv['csv_sha256']}",
        )
        add(
            "凭据文件", sha256_hex(cred_raw) == pv["credential_sha256"],
            f"快照凭据实际摘要 {sha256_hex(cred_raw)}，"
            f"登记 {pv['credential_sha256']}",
        )
        payload, errs = parse_credential(cred_raw)
        if errs:
            for e in errs:
                add("凭据格式", False, e)
        else:
            add(
                "凭据版本", payload["version"] == version,
                f"凭据声明 v{payload['version']}，选定 v{version}",
            )
            add(
                "凭据批次号", payload["batch_no"] == pv["batch_no"],
                f"凭据批次号 {payload['batch_no']}，登记 {pv['batch_no']}",
            )
            add(
                "凭据 CSV 摘要", payload["csv_sha256"] == pv["csv_sha256"],
                f"凭据记录 {payload['csv_sha256']}，登记 {pv['csv_sha256']}",
            )
            add(
                "凭据行数", payload.get("row_count") == pv["row_count"],
                f"凭据行数 {payload.get('row_count')}，登记 {pv['row_count']}",
            )
            add(
                "前版凭据", payload["prev_credential_sha256"]
                == pv["prev_credential_sha256"],
                "凭据声明无前驱（链首版）"
                if pv["prev_credential_sha256"] is None
                else f"凭据前驱 {payload['prev_credential_sha256']}，"
                f"登记链 {pv['prev_credential_sha256']}",
            )

        if pv["prev_credential_sha256"] is None:
            is_first = first is not None and first["version"] == version
            add(
                "链条起点", is_first,
                "该版本为本系统取证链首版（无前驱）"
                if is_first else
                "该版本声明无前驱，但不是链中登记的第一版"
                "（历史旧版无凭据，链条可能被截断）",
            )
        else:
            add(
                "前版凭据存在", prev is not None,
                f"前驱摘要 {pv['prev_credential_sha256']} 对应登记 v"
                f"{prev['version']}" if prev is not None else
                f"登记中找不到前驱凭据 {pv['prev_credential_sha256']}（链条断裂）",
            )

        return {
            "version": version,
            "checks": checks,
            "ok": bool(checks) and all(c["ok"] for c in checks),
            "reasons": [f"{c['name']}：{c['detail']}" for c in checks if not c["ok"]],
        }

    def get_session(self, token: str):
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM revision_sessions WHERE token = ?", (token,)
            ).fetchone()
            if row is None:
                return None
            data = dict(row)
            data["rows"] = json.loads(data["payload"])
            return data

    def create_session(self, batch_no: str, base_version: int, rows: list[dict]) -> str:
        token = uuid.uuid4().hex
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO revision_sessions(token, batch_no, base_version, payload,"
                " created_at, status) VALUES (?,?,?,?,?,?)",
                (
                    token,
                    batch_no,
                    base_version,
                    json.dumps(rows, ensure_ascii=False),
                    _now(),
                    "pending",
                ),
            )
        return token

    def mark_obsolete(self, token: str, current_version: int) -> None:
        """预览在确认前已被其他发布超越：作废该会话，强制重新预览。"""
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE revision_sessions SET status='obsolete' "
                "WHERE token=? AND status='pending'",
                (token,),
            )
            if cur.rowcount:
                self._log(
                    conn, "conflict",
                    f"会话 {token[:8]} 已过期（当前 v{current_version}），"
                    "拒绝覆盖，需重新预览",
                )

    def cancel_session(self, token: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE revision_sessions SET status='cancelled' "
                "WHERE token=? AND status='pending'",
                (token,),
            )
            if cur.rowcount:
                self._log(conn, "cancel", f"放弃修订会话 {token[:8]}")
                return cur.rowcount > 0
        return False

    # ---------- 预览差异 ----------
    def preview_diff(self, new_rows: list[dict]) -> dict:
        """与当前已发布版本比对，返回 增/改/删/不变 四类差异。"""
        old = {(r["sample_no"], r["analyte"]): r["concentration"]
               for r in self.current_rows()}
        new = {(r["sample_no"], r["analyte"]): r["concentration"] for r in new_rows}
        inserts, updates, deletes, unchanged = [], [], [], []
        for key, val in new.items():
            if key not in old:
                inserts.append({"sample_no": key[0], "analyte": key[1], "new": val})
            elif old[key] != val:
                updates.append(
                    {"sample_no": key[0], "analyte": key[1],
                     "old": old[key], "new": val}
                )
            else:
                unchanged.append({"sample_no": key[0], "analyte": key[1], "value": val})
        for key, val in old.items():
            if key not in new:
                deletes.append({"sample_no": key[0], "analyte": key[1], "old": val})
        inserts.sort(key=lambda d: (d["sample_no"], d["analyte"]))
        updates.sort(key=lambda d: (d["sample_no"], d["analyte"]))
        deletes.sort(key=lambda d: (d["sample_no"], d["analyte"]))
        unchanged.sort(key=lambda d: (d["sample_no"], d["analyte"]))
        return {
            "inserts": inserts, "updates": updates,
            "deletes": deletes, "unchanged": unchanged,
        }

    # ---------- 确认发布（核心事务） ----------
    def publish(self, token: str) -> tuple[int, int]:
        """确认整批替换。返回 (新版本号, 行数)。

        并发控制：BEGIN IMMEDIATE 立即拿写锁，事务内再次核对会话基线版本，
        若期间已有别人发布（current_version > base_version），本会话作废，
        抛出 PublishConflictError，调用方须重新预览。
        """
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            session = conn.execute(
                "SELECT * FROM revision_sessions WHERE token=?", (token,)
            ).fetchone()
            if session is None:
                raise PublishConflictError("修订会话不存在或已失效，请重新上传预览")
            if session["status"] != "pending":
                label = {"published": "已发布", "obsolete": "已过期",
                         "cancelled": "已取消"}.get(session["status"], session["status"])
                raise PublishConflictError(f"该修订会话{label}，请重新上传预览")

            reg = conn.execute("SELECT * FROM registry WHERE id=1").fetchone()
            current_version = reg["current_version"] if reg else 0
            if session["base_version"] != current_version:
                conn.execute(
                    "UPDATE revision_sessions SET status='obsolete' WHERE token=?",
                    (token,),
                )
                self._log(
                    conn, "conflict",
                    f"会话 {token[:8]} 基于 v{session['base_version']} 发起，"
                    f"当前已为 v{current_version}，拒绝覆盖，需重新预览",
                )
                raise PublishConflictError(
                    f"版本已变化：您基于 v{session['base_version']} 预览，"
                    f"当前已是 v{current_version}，请重新预览后再发布"
                )

            rows = json.loads(session["payload"])
            new_version = current_version + 1
            csv_text = render_csv(rows)
            content_hash = hashlib.sha256(csv_text.encode("utf-8")).hexdigest()
            published_at = _now()

            activation = conn.execute(
                "SELECT version FROM evidence_activation WHERE id = 1"
            ).fetchone()
            if activation is None:
                raise PublishConflictError(
                    "取证登记尚未初始化，请重启应用后再发布"
                )
            active_from = activation["version"]

            # 当前版本属于取证启用前（或是首次发布）：本版起链首，不补造旧版证明
            if reg is None or reg["current_version"] < active_from:
                chain_start = new_version
                prev_credential_sha = None
                prev_version = None
            else:
                chain_start = active_from
                prev_pv = conn.execute(
                    "SELECT version, credential_sha256 FROM published_versions "
                    "WHERE version = ?",
                    (current_version,),
                ).fetchone()
                prev_credential_sha = (
                    prev_pv["credential_sha256"] if prev_pv else None
                )
                prev_snapshot_version = prev_pv["version"] if prev_pv else None
                if prev_pv is None:
                    # 链上缺前版凭据（仅可能因旧数据/人工删库）：宁可不发，不造假凭据
                    raise PublishConflictError(
                        f"v{current_version} 的发布凭据缺失，无法为 v{new_version} "
                        "接续链条；请联系管理员核对数据目录"
                    )

            credential_text = build_credential(
                version=new_version,
                batch_no=session["batch_no"],
                row_count=len(rows),
                published_at=published_at,
                csv_sha256=content_hash,
                prev_credential_sha256=prev_credential_sha,
            )
            credential_sha = sha256_hex(credential_text)

            # 先把历史快照写入 data 目录并 fsync，再动下游文件、最后登记。
            # 任何一步失败：事务回滚，并把下游 CSV/凭据恢复成旧登记的内容，
            # 保证现场不残留指向未登记版本的文件；即使进程当场崩溃，
            # 重启时 recover() 也会按旧登记回滚。
            version_dir = os.path.join(self.data_dir, "versions", f"v{new_version}")
            self._atomic_write_in(version_dir, "published_results.csv",
                                  csv_text.encode("utf-8"))
            self._atomic_write_in(version_dir, CREDENTIAL_FILENAME,
                                  credential_text.encode("utf-8"))

            previous_csv = None
            if os.path.exists(self.live_path):
                with open(self.live_path, "rb") as fh:
                    previous_csv = fh.read()
            previous_credential = None
            if reg is not None and current_version >= active_from:
                prev_pv = conn.execute(
                    "SELECT credential_text FROM published_versions WHERE version=?",
                    (current_version,),
                ).fetchone()
                if prev_pv is not None:
                    previous_credential = prev_pv["credential_text"].encode("utf-8")

            try:
                # 原子替换下游 CSV 与凭据（旧文件在 replace 前始终完整可用）
                self._atomic_write(csv_text)
                self._atomic_write_bytes(
                    self.credential_path, credential_text.encode("utf-8"),
                    ".tmp-credential-",
                )

                # 再落库登记；若此后进程崩溃，重启 recover() 以登记为准核对
                conn.executemany(
                    "INSERT INTO results(version, batch_no, sample_no, analyte,"
                    " concentration) VALUES (?,?,?,?,?)",
                    [
                        (new_version, session["batch_no"], r["sample_no"],
                         r["analyte"], r["concentration"])
                        for r in rows
                    ],
                )
                conn.execute(
                    "INSERT INTO published_versions(version, batch_no, row_count,"
                    " published_at, csv_sha256, csv_content, credential_text,"
                    " credential_sha256, prev_credential_sha256, evidence_from_version)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (
                        new_version, session["batch_no"], len(rows), published_at,
                        content_hash, csv_text, credential_text, credential_sha,
                        prev_credential_sha, chain_start,
                    ),
                )
                conn.execute(
                    "INSERT INTO registry(id, current_version, batch_no, row_count,"
                    " published_at, content_hash) VALUES (1,?,?,?,?,?) "
                    "ON CONFLICT(id) DO UPDATE SET"
                    " current_version=excluded.current_version,"
                    " batch_no=excluded.batch_no, row_count=excluded.row_count,"
                    " published_at=excluded.published_at,"
                    " content_hash=excluded.content_hash",
                    (new_version, session["batch_no"], len(rows), published_at,
                     content_hash),
                )
                conn.execute(
                    "UPDATE revision_sessions SET status='published' WHERE token=?",
                    (token,),
                )
                self._log(
                    conn, "publish",
                    f"发布 v{new_version}：批次 {session['batch_no']}，{len(rows)} 行，"
                    f"sha256={content_hash[:12]}…，凭据 sha256={credential_sha[:12]}…"
                    + (
                        "（取证链首版，无前驱）"
                        if prev_credential_sha is None
                        else f"（前版凭据 {prev_credential_sha[:12]}…）"
                    ),
                )
                # 显式提交：若提交本身失败，也要走回滚分支恢复下游文件
                conn.commit()
            except BaseException:
                # 事务会随连接关闭回滚；这里把下游文件恢复到旧登记内容
                try:
                    if previous_csv is not None:
                        self._atomic_write_bytes(
                            self.live_path, previous_csv, ".tmp-publish-"
                        )
                    else:
                        try:
                            os.unlink(self.live_path)
                        except OSError:
                            pass
                    if previous_credential is not None:
                        self._atomic_write_bytes(
                            self.credential_path, previous_credential,
                            ".tmp-credential-",
                        )
                    else:
                        try:
                            os.unlink(self.credential_path)
                        except OSError:
                            pass
                except OSError:
                    pass
                # 走到这里说明本次事务必将回滚（提交在 with 退出时才发生），
                # 未提交的版本快照不得留下冒充历史版本。
                shutil.rmtree(version_dir, ignore_errors=True)
                raise
            return new_version, len(rows)

    # ---------- 页面辅助 ----------
    @staticmethod
    def display_concentration(value: float) -> str:
        return format_concentration(value)
