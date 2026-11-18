"""Flask 路由：上传校验 → 预览增删改 → 确认整批替换。"""
from __future__ import annotations

import io
import os
import secrets
import sqlite3

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from .evidence import pretty_credential
from .storage import (
    CREDENTIAL_FILENAME,
    LIVE_FILENAME,
    PublishConflictError,
    Storage,
)
from .validation import format_concentration, validate_csv

MAX_UPLOAD_BYTES = 16 * 1024 * 1024


def create_app(data_dir: str | None = None, downstream_dir: str | None = None) -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES

    base = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
    data_dir = data_dir or os.environ.get("WQ_DATA_DIR") or os.path.join(base, "data")
    downstream_dir = (
        downstream_dir
        or os.environ.get("WQ_DOWNSTREAM_DIR")
        or os.path.join(base, "downstream")
    )

    secret_path = os.path.join(data_dir, "flask_secret")
    os.makedirs(data_dir, exist_ok=True)
    if os.path.exists(secret_path):
        with open(secret_path, "rb") as fh:
            app.secret_key = fh.read()
    else:
        key = secrets.token_bytes(32)
        with open(secret_path, "wb") as fh:
            fh.write(key)
        os.chmod(secret_path, 0o600)
        app.secret_key = key

    storage = Storage(data_dir, downstream_dir)
    app.storage = storage  # 供自测脚本直接访问

    @app.template_filter("conc")
    def _conc(value):
        return format_concentration(value)

    @app.get("/")
    def index():
        reg = storage.current_registry()
        rows = storage.current_rows()
        events = storage.recent_events()
        return render_template(
            "index.html", reg=reg, rows=rows, events=events,
            live_filename=LIVE_FILENAME,
            credential_filename=CREDENTIAL_FILENAME,
        )

    @app.post("/preview")
    def preview():
        upload = request.files.get("csv_file")
        batch_no = request.form.get("batch_no", "")
        if upload is None or not upload.filename:
            flash("请选择仪器导出的 CSV 文件", "error")
            return redirect(url_for("index"))
        raw = upload.read()
        if len(raw) > MAX_UPLOAD_BYTES:
            flash("CSV 文件超过 16MB 上限", "error")
            return redirect(url_for("index"))

        rows, errors = validate_csv(raw, batch_no)
        if errors:
            for msg in errors:
                flash(msg, "error")
            return redirect(url_for("index"))

        reg = storage.current_registry()
        base_version = reg["current_version"] if reg else 0
        token = storage.create_session(batch_no.strip(), base_version, rows)
        diff = storage.preview_diff(rows)
        storage.log(
            "preview",
            f"会话 {token[:8]} 基于 v{base_version} 预览批次 {batch_no.strip()}："
            f"新增 {len(diff['inserts'])} / 修改 {len(diff['updates'])} / "
            f"撤回 {len(diff['deletes'])} / 不变 {len(diff['unchanged'])}",
        )
        return render_template(
            "preview.html",
            token=token,
            batch_no=batch_no.strip(),
            base_version=base_version,
            current_version=base_version,
            rows=rows,
            diff=diff,
            live_filename=LIVE_FILENAME,
        )

    @app.post("/publish/<token>")
    def publish(token):
        session = storage.get_session(token)
        if session is None:
            flash("修订会话不存在或已过期，请重新上传 CSV", "error")
            return redirect(url_for("index"))

        reg = storage.current_registry()
        current_version = reg["current_version"] if reg else 0
        if session["status"] != "pending" or session["base_version"] != current_version:
            # 会话在预览期间被别的发布超越：作废会话，展示基于旧版的差异，要求重新预览
            if session["status"] == "pending":
                storage.mark_obsolete(token, current_version)
                stale_reason = (
                    f"您基于 v{session['base_version']} 发起修订，"
                    f"但当前版本已变为 v{current_version}（另一页面已成功发布）"
                )
            else:
                reason_map = {
                    "published": "该修订已经发布，不能重复发布",
                    "obsolete": "该预览已被更新的发布超越而作废",
                    "cancelled": "该修订已被放弃（取消）",
                }
                stale_reason = reason_map.get(session["status"], "该修订会话已失效")
            diff = storage.preview_diff(session["rows"])
            storage.log(
                "conflict",
                f"会话 {token[:8]} 发布被拒（基线 v{session['base_version']}，"
                f"当前 v{current_version}，状态 {session['status']}）",
            )
            return render_template(
                "preview.html",
                token=token,
                batch_no=session["batch_no"],
                base_version=session["base_version"],
                current_version=current_version,
                rows=session["rows"],
                diff=diff,
                stale=True,
                stale_reason=stale_reason,
                live_filename=LIVE_FILENAME,
            ), 409

        try:
            new_version, row_count = storage.publish(token)
        except PublishConflictError as exc:
            flash(str(exc), "error")
            return redirect(url_for("index"))
        except sqlite3.OperationalError as exc:  # 极端并发下写锁等待超时
            app.logger.warning("publish lock contention: %s", exc)
            flash("当前有其他发布正在写入，请稍后重新预览再发布", "error")
            return redirect(url_for("index"))
        flash(f"发布成功：v{new_version} 已生效，共 {row_count} 行", "success")
        return redirect(url_for("index"))

    @app.post("/cancel/<token>")
    def cancel(token):
        if storage.cancel_session(token):
            flash("已放弃本次修订，当前发布版本未受影响", "info")
        return redirect(url_for("index"))

    @app.get("/published.csv")
    def published_csv():
        if not os.path.exists(storage.live_path):
            abort(404, description="尚无已发布的 CSV")
        return send_file(
            storage.live_path, mimetype="text/csv",
            download_name=LIVE_FILENAME, as_attachment=False,
        )

    # ---------- 浏览器取证页 ----------
    @app.get("/evidence")
    def evidence():
        history = storage.full_history()
        requested = request.args.get("version", type=int)
        if requested is None and history:
            requested = history[-1]["version"]
        selected = None
        if requested is not None:
            selected = next((h for h in history if h["version"] == requested), None)
            if selected is None:
                flash(f"版本 v{requested} 不存在", "error")
                return redirect(url_for("evidence"))

        check = None
        check_version = request.args.get("check", type=int)
        if check_version is not None:
            pv = storage.published_version(check_version)
            if pv is None:
                flash(f"版本 v{check_version} 没有发布凭据可供核验", "error")
            else:
                check = storage.verify_registered_version(check_version)

        return render_template(
            "evidence.html",
            history=history,
            selected=selected,
            activation_version=storage.evidence_activation_version(),
            credential_filename=CREDENTIAL_FILENAME,
            check=check,
        )

    @app.get("/evidence/<int:version>/credential.json")
    def evidence_credential(version: int):
        payload, raw, digest = storage.version_credential(version)
        if raw is None:
            abort(404, description=f"v{version} 没有发布凭据（取证启用前的版本不补造）")
        resp = send_file(
            io.BytesIO(raw), mimetype="application/json",
            download_name=f"v{version}-{CREDENTIAL_FILENAME}",
            as_attachment=True,
        )
        resp.headers["X-Credential-SHA256"] = digest
        return resp

    @app.get("/evidence/<int:version>/data.csv")
    def evidence_version_csv(version: int):
        text = storage.version_csv_text(version)
        if text is None:
            abort(404, description=f"版本 v{version} 不存在")
        return send_file(
            io.BytesIO(text.encode("utf-8")), mimetype="text/csv",
            download_name=f"v{version}-{LIVE_FILENAME}", as_attachment=True,
        )

    @app.post("/evidence/verify")
    def evidence_verify():
        csv_upload = request.files.get("csv_file")
        cred_upload = request.files.get("credential_file")
        csv_raw = None
        if csv_upload is not None and csv_upload.filename:
            csv_raw = csv_upload.read(MAX_UPLOAD_BYTES + 1)
            if len(csv_raw) > MAX_UPLOAD_BYTES:
                flash("CSV 文件超过 16MB 上限", "error")
                return redirect(url_for("evidence"))
        cred_raw = None
        if cred_upload is not None and cred_upload.filename:
            cred_raw = cred_upload.read(MAX_UPLOAD_BYTES + 1)
            if len(cred_raw) > MAX_UPLOAD_BYTES:
                flash("凭据文件超过 16MB 上限", "error")
                return redirect(url_for("evidence"))
        if csv_raw is None and cred_raw is None:
            flash("请至少选择一份要核验的文件", "error")
            return redirect(url_for("evidence"))

        # 一次核验只读取一次登记快照；期间的新发布会另开版本，不改变本次结论
        result = storage.verify_uploaded_evidence(csv_raw, cred_raw)
        storage.log(
            "verify",
            f"取证核验：CSV={'有' if csv_raw is not None else '无'}，"
            f"凭据={'有' if cred_raw is not None else '无'}，"
            f"结论={'通过' if result['ok'] else '不通过'}",
        )
        preview_limit = 64 * 1024
        csv_text = None
        if csv_raw is not None:
            csv_text = csv_raw[:preview_limit].decode("utf-8-sig", errors="replace")
            if len(csv_raw) > preview_limit:
                csv_text += "\n…（文件较大，页面仅展示前 64KB）"
        return render_template(
            "verify.html",
            result=result,
            csv_name=csv_upload.filename if csv_raw is not None else None,
            cred_name=cred_upload.filename if cred_raw is not None else None,
            csv_text=csv_text,
            cred_text=pretty_credential(result["credential_payload"], cred_raw),
            credential_filename=CREDENTIAL_FILENAME,
        )

    @app.errorhandler(413)
    def too_large(_):
        flash("上传文件超过 16MB 上限", "error")
        if request.path.startswith("/evidence"):
            return redirect(url_for("evidence"))
        return redirect(url_for("index"))

    return app
