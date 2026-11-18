"""发布凭据（evidence credential）的构造、序列化与上传文件解析。

一份凭据是一个 UTF-8 JSON 文件，至少包含：

* ``version``：版本号；
* ``batch_no``：该版批次号；
* ``csv_sha256``：该版 CSV 的 SHA-256；
* ``prev_credential_sha256``：前一版凭据文件字节的 SHA-256；
  链首版为 ``null``（无前驱）。

凭据文件本身的摘要 = SHA-256(文件原始字节)。为了让同一凭据文件在任何机器上
都得到同一摘要，生成时使用固定字段顺序与紧凑分隔符（``sort_keys`` +
``separators``），下载时直接返回数据库保存的这份字节，不做二次格式化。
"""
from __future__ import annotations

import hashlib
import json
import re

CREDENTIAL_TYPE = "wq-publish-evidence-v1"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def canonical_json(payload: dict) -> str:
    """固定、可复现的 JSON 文本（凭据文件下载与摘要都基于它）。"""
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def build_credential(
    *,
    version: int,
    batch_no: str,
    row_count: int,
    published_at: str,
    csv_sha256: str,
    prev_credential_sha256: str | None,
) -> str:
    """生成凭据文件内容（不含凭据自身的摘要，避免循环定义）。"""
    return canonical_json(
        {
            "credential_type": CREDENTIAL_TYPE,
            "version": int(version),
            "batch_no": batch_no,
            "row_count": int(row_count),
            "published_at": published_at,
            "csv_sha256": csv_sha256,
            "prev_credential_sha256": prev_credential_sha256,
        }
    )


def parse_credential(raw: bytes) -> tuple[dict | None, list[str]]:
    """解析上传的凭据文件。

    返回 (payload, errors)。errors 为空才说明结构和字段类型合法；合法不代表
    该凭据属于本系统——是否与登记一致由核验流程继续判断。
    """
    errors: list[str] = []
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None, ["凭据文件必须为 UTF-8 编码的 JSON"]
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        return None, [f"凭据不是合法 JSON：{exc}"]
    if not isinstance(payload, dict):
        return None, ["凭据 JSON 顶层必须是对象"]

    ctype = payload.get("credential_type")
    if ctype is not None and ctype != CREDENTIAL_TYPE:
        errors.append(
            f"凭据类型 {ctype!r} 不认识（应为 {CREDENTIAL_TYPE}）"
        )

    version = payload.get("version")
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or version < 1
    ):
        errors.append("凭据缺少合法的 version（正整数）")

    batch_no = payload.get("batch_no")
    if not isinstance(batch_no, str) or not batch_no.strip():
        errors.append("凭据缺少合法的 batch_no")

    csv_sha = payload.get("csv_sha256")
    if not isinstance(csv_sha, str) or not _HEX64.match(csv_sha):
        errors.append("凭据缺少合法的 csv_sha256（64 位小写十六进制）")

    prev = payload.get("prev_credential_sha256")
    if prev is not None and (not isinstance(prev, str) or not _HEX64.match(prev)):
        errors.append(
            "prev_credential_sha256 必须为 null 或 64 位小写十六进制摘要"
        )

    row_count = payload.get("row_count")
    if row_count is not None and (
        not isinstance(row_count, int) or isinstance(row_count, bool) or row_count < 0
    ):
        errors.append("row_count 必须为非负整数")

    return payload, errors


def pretty_credential(payload: dict | None, raw: bytes | None = None) -> str:
    if payload is not None:
        return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    if raw:
        try:
            return raw.decode("utf-8", errors="replace")
        except Exception:  # pragma: no cover - 防御性
            return ""
    return ""
