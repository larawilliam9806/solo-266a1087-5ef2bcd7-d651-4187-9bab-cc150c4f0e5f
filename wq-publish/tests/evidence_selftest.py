"""发布凭据（取证）自测：python -I tests/evidence_selftest.py

覆盖：
1. 启用前旧版标记无凭据、不补造；
2. 启用后每版生成凭据，字段正确，链首无前驱，后续版本前驱 = 上一版凭据摘要；
3. 按版本下载 CSV / 凭据，内容与当时发布一致（后续发布不改变历史版本下载）；
4. 上传两份文件核验：通过、CSV 被改、凭据被改、错配版本、接错链条；
5. 核验只依据选定版本：核验过程中发生新发布，结论不变；
6. 发布失败（基线过期）不生成凭据；并发只产生一个版本、不分叉；
7. 重启恢复：下游凭据损坏/缺失按登记重建；旧版目录出现凭据被隔离；
    已登记快照被篡改/删除按登记重建；未登记快照目录被隔离。
8. docker compose 配置文件存在且可解析为 YAML（不依赖 PyYAML 时跳过）。
"""
import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wq_publish.app import create_app
from wq_publish.evidence import parse_credential
from wq_publish.storage import CREDENTIAL_FILENAME, LIVE_FILENAME

PASS, FAIL = 0, 0
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLE_DIR = os.path.join(ROOT, "examples")


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL += 1
        print(f"  ✗ {name} {detail}")


def read_example(fname):
    with open(os.path.join(EXAMPLE_DIR, fname), "rb") as fh:
        return fh.read()


def upload(client, fname, batch_no="B1"):
    return client.post(
        "/preview",
        data={"batch_no": batch_no,
              "csv_file": (io.BytesIO(read_example(fname)), fname)},
        content_type="multipart/form-data",
    )


def token_of(resp):
    return re.search(rb'/publish/([0-9a-f]+)', resp.data).group(1).decode()


def publish(client, fname, batch_no="B1"):
    resp = upload(client, fname, batch_no)
    assert resp.status_code == 200, resp.status_code
    return client.post(f"/publish/{token_of(resp)}")


def sha(data):
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


tmp = tempfile.mkdtemp(prefix="wq-evidence-")
data_dir = os.path.join(tmp, "data")
down_dir = os.path.join(tmp, "downstream")

# ---------------- 1. 启用前旧版：无凭据、不补造 ----------------
print("== 1. 启用前旧版 ==")
# 先用“旧程序”的写法手工造出 v1、v2 登记（只写 results/registry），
# 模拟部署本功能之前已经存在的历史版本。
os.makedirs(data_dir, exist_ok=True)
os.makedirs(down_dir, exist_ok=True)
app = create_app(data_dir=data_dir, downstream_dir=down_dir)
legacy = app.storage
with legacy._connect() as conn:
    conn.execute("DELETE FROM evidence_activation")
    conn.execute("DELETE FROM published_versions")
from wq_publish.validation import render_csv
legacy_rows = [
    {"sample_no": "S001", "analyte": "氨氮", "concentration": 1.25},
    {"sample_no": "S002", "analyte": "COD", "concentration": 35.0},
]
legacy_csv = render_csv(legacy_rows)
with legacy._connect() as conn:
    conn.executemany(
        "INSERT INTO results(version,batch_no,sample_no,analyte,concentration)"
        " VALUES (?,?,?,?,?)",
        [(1, "OLD-1", r["sample_no"], r["analyte"], r["concentration"])
         for r in legacy_rows],
    )
    conn.execute(
        "INSERT INTO results(version,batch_no,sample_no,analyte,concentration)"
        " VALUES (2,'OLD-2','S009','总磷',0.1)"
    )
    conn.execute(
        "INSERT OR REPLACE INTO registry(id,current_version,batch_no,row_count,"
        "published_at,content_hash) VALUES (1,2,'OLD-2',1,'2026-01-01T00:00:00+00:00',?)",
        (sha(render_csv([{"sample_no": "S009", "analyte": "总磷",
                          "concentration": 0.1}])),),
    )
# 旧版下游文件（无凭据）
with open(os.path.join(down_dir, LIVE_FILENAME), "wb") as fh:
    fh.write(render_csv([{"sample_no": "S009", "analyte": "总磷",
                          "concentration": 0.1}]).encode())

app = create_app(data_dir=data_dir, downstream_dir=down_dir)
client = app.test_client()
st = app.storage
check("首次启动不补造旧版凭据", st.published_version(2) is None)
check("启用版本 = 下一个新发布（v3）", st.evidence_activation_version() == 3,
      str(st.evidence_activation_version()))
check("下游目录没有被凭空创建凭据",
      not os.path.exists(os.path.join(down_dir, CREDENTIAL_FILENAME)))

resp = client.get("/evidence")
check("取证页 200 且列出旧版无凭据",
      resp.status_code == 200 and "无凭据".encode() in resp.data)
check("旧版 CSV 仍可按版本下载",
      client.get("/evidence/1/data.csv").status_code == 200)
check("旧版凭据下载返回 404（不补造）",
      client.get("/evidence/2/credential.json").status_code == 404)
check("旧版凭据内容即使被手工上传也无法通过",
      not st.verify_uploaded_evidence(
          open(os.path.join(down_dir, LIVE_FILENAME), "rb").read(),
          json.dumps({"version": 2, "batch_no": "OLD-2", "csv_sha256": "0" * 64,
                      "prev_credential_sha256": None}).encode(),
      )["ok"])

# ---------------- 2. 启用后的凭据链 ----------------
print("== 2. 启用后的凭据链 ==")
resp = publish(client, "batch_v1.csv", "NEW-3")
check("新发布成功 → v3", resp.status_code == 302
      and st.current_registry()["current_version"] == 3)
pv3 = st.published_version(3)
cred3, raw3, sha3 = st.version_credential(3)
check("v3 生成凭据", pv3 is not None and cred3 is not None)
check("链首版凭据无前驱", cred3["prev_credential_sha256"] is None)
check("凭据记录的 CSV 摘要 = 登记摘要",
      cred3["csv_sha256"] == pv3["csv_sha256"])
check("凭据记录版本/批次号", cred3["version"] == 3 and cred3["batch_no"] == "NEW-3")
check("凭据文件摘要 = SHA-256(凭据原始字节)", sha(raw3) == sha3)
check("下游目录也生成凭据文件",
      sha(open(os.path.join(down_dir, CREDENTIAL_FILENAME), "rb").read()) == sha3)
check("下载的凭据字节与登记完全一致",
      client.get("/evidence/3/credential.json").data == raw3)

resp = publish(client, "batch_v2_revision.csv", "NEW-4")
check("再发布一次 → v4", st.current_registry()["current_version"] == 4)
cred4, raw4, sha4 = st.version_credential(4)
check("v4 前驱 = v3 凭据文件摘要",
      cred4["prev_credential_sha256"] == sha3)

# 下载历史版本：内容必须是当时发布的，不能是当前版本
dl3 = client.get("/evidence/3/data.csv").data
check("v3 CSV 下载仍为当版内容（当时发布的 5 行）",
      dl3 == pv3["csv_content"].encode() and b"S003" in dl3
      and b"1.25" in dl3 and b"S004" not in dl3)
check("v4 凭据链在取证页可见",
      b"v4" in client.get("/evidence?version=4").data)

# ---------------- 3. 上传两份文件核验 ----------------
print("== 3. 上传核验 ==")
pv4_csv = st.published_version(4)["csv_content"].encode()


def verify(csv_bytes=None, cred_bytes=None):
    data = {}
    if csv_bytes is not None:
        data["csv_file"] = (io.BytesIO(csv_bytes), "saved.csv")
    if cred_bytes is not None:
        data["credential_file"] = (io.BytesIO(cred_bytes), "saved.json")
    return client.post("/evidence/verify", data=data,
                       content_type="multipart/form-data")


r = verify(pv4_csv, raw4)
check("原样两份文件 → 核验通过", r.status_code == 200 and "核验通过".encode() in r.data)
r = verify(pv3["csv_content"].encode(), raw3)
check("历史版本 v3 的两份文件 → 核验通过",
      "核验通过".encode() in r.data)
r = verify(pv4_csv, raw3)
check("CSV 与凭据错配 → 不通过且说明配对不符",
      "核验不通过".encode() in r.data and "配对".encode() in r.data)
tampered_csv = pv4_csv.replace(b"S001", b"S999")
r = verify(tampered_csv, raw4)
check("CSV 被改 → 不通过并指出摘要不在登记中",
      "核验不通过".encode() in r.data and "不在任何登记版本".encode() in r.data)
tampered_cred = raw4.replace(b"NEW-4", b"NEW-X")
r = verify(pv4_csv, tampered_cred)
check("凭据被改（批次号）→ 不通过",
      "核验不通过".encode() in r.data and "凭据摘要".encode() in r.data)
reformatted = json.dumps(json.loads(raw4), indent=2, sort_keys=True).encode()
r = verify(pv4_csv, reformatted)
check("凭据仅重新格式化 → 文件摘要不符（链上凭据按原始字节认定）",
      "核验不通过".encode() in r.data and "不是本系统登记的任何凭据".encode() in r.data)
r = verify(None, raw4)
check("只上传凭据 → 不通过（无法核对 CSV）",
      "核验不通过".encode() in r.data and "仅上传了凭据".encode() in r.data)
r = verify(pv4_csv, None)
check("只上传 CSV → 不通过（无法核对链条）",
      "核验不通过".encode() in r.data and "仅上传了 CSV".encode() in r.data)
r = verify(pv4_csv, b"{not json")
check("非 JSON 凭据 → 不通过", "核验不通过".encode() in r.data)

# 伪造“链条接错”：声明前驱为 v3 的凭据摘要，但版本号写成 4 之后的一版
forged = json.loads(raw4)
forged["version"] = 5
forged_raw = json.dumps(forged, sort_keys=True, separators=(",", ":")).encode()
r = verify(None, forged_raw)
check("伪造未发布版本号 → 不通过（登记无该版）",
      "核验不通过".encode() in r.data and "没有该版本的凭据记录".encode() in r.data)

# ---------------- 4. 核验结论只依据选定版本 ----------------
print("== 4. 核验期间的新发布不改变结论 ==")
# 先取 v4 的两份文件，然后发布 v5，再用旧文件核验：结论仍是 v4 通过
before = st.published_version(4)
publish(client, "batch_v1.csv", "NEW-5")
check("期间已发布到 v5", st.current_registry()["current_version"] == 5)
r = verify(before["csv_content"].encode(),
           before["credential_text"].encode())
check("核验 v4 旧文件仍通过（不因新发布改变）",
      "核验通过".encode() in r.data)
check("核验页显示的登记版本仍是 v4",
      b"v4" in r.data)
r = client.get("/evidence?check=4")
check("选定版本核验入口只核验 v4 且通过",
      "核验通过".encode() in r.data)
r = client.get("/evidence?check=5")
check("选定 v5 核验也通过", "核验通过".encode() in r.data)

# ---------------- 5. 发布失败/并发不产生凭据、不分叉 ----------------
print("== 5. 失败与并发 ==")
versions_before = st.all_version_numbers()
r_a = upload(client, "batch_v1.csv", "RACE-A")
r_b = upload(client, "batch_v2_revision.csv", "RACE-B")
res_a = client.post(f"/publish/{token_of(r_a)}")
res_b = client.post(f"/publish/{token_of(r_b)}")
check("并发只有一个成功、一个 409",
      {res_a.status_code, res_b.status_code} == {302, 409})
versions_after = st.all_version_numbers()
check("并发只新增一个版本、不分叉",
      len(versions_after) == len(versions_before) + 1
      and all(v in versions_after for v in versions_before))
newest = versions_after[-1]
check("新版本凭据前驱 = 上一版凭据摘要",
      st.version_credential(newest)[0]["prev_credential_sha256"]
      == st.version_credential(newest - 1)[2])
check("每个凭据版本的 CSV 摘要都能在其快照中复算出来",
      all(sha(st.published_version(v)["csv_content"]) ==
          st.published_version(v)["csv_sha256"]
          for v in versions_after if v >= 3))

# 直接破坏链上前一版的凭据记录，验证发布被拒绝而不是造出断链
cur_before = st.current_registry()["current_version"]
with st._connect() as conn:
    conn.execute("DELETE FROM published_versions WHERE version = ?", (cur_before,))
resp = publish(client, "batch_v1.csv", "BROKEN-CHAIN")
check("前版凭据缺失时拒绝发布（宁可不发，不造断链凭据）",
      resp.status_code == 302 and st.current_registry()["current_version"] == cur_before
      and st.published_version(cur_before + 1) is None)
resp = publish(client, "batch_v1.csv", "BROKEN-CHAIN-AGAIN")
check("拒绝发布时给出明确错误并提示重新预览",
      resp.status_code == 302 and "发布凭据缺失".encode() in client.get("/").data
      and st.current_registry()["current_version"] == cur_before)
# 人工恢复被删记录：从下游当前文件无法还原，故直接整体重建该版记录
# （模拟管理员按快照目录修复数据库；快照目录仍在）
snap_cur = os.path.join(data_dir, "versions", f"v{cur_before}")
recovered_csv = open(
    os.path.join(snap_cur, "published_results.csv"), "rb").read().decode()
recovered_cred = open(
    os.path.join(snap_cur, CREDENTIAL_FILENAME), "rb").read()
with st._connect() as conn:
    conn.execute(
        "INSERT INTO published_versions(version, batch_no, row_count, published_at,"
        " csv_sha256, csv_content, credential_text, credential_sha256,"
        " prev_credential_sha256, evidence_from_version) VALUES"
        " (?,?,?,?,?,?,?,?,?,?)",
        (cur_before, "RESTORED", len(recovered_csv.splitlines()) - 1,
         "2026-01-01T00:00:00+00:00", sha(recovered_csv), recovered_csv,
         recovered_cred.decode(), sha(recovered_cred),
         st.published_version(cur_before - 1)["credential_sha256"], 3),
    )
pv5 = None  # 后续恢复测试从当前登记读取，不依赖变量

# ---------------- 6. 重启恢复 ----------------
print("== 6. 重启恢复（凭据与快照）==")
cur = st.current_registry()["current_version"]
pv_cur = st.published_version(cur)
if pv_cur is None:
    # 当前版本正是被删记录的 v5：先补发一版，获得目标状态
    publish(client, "batch_v1.csv", "RECOVER-BASE")
    cur = st.current_registry()["current_version"]
    pv_cur = st.published_version(cur)

cred_path = os.path.join(down_dir, CREDENTIAL_FILENAME)
with open(cred_path, "wb") as fh:
    fh.write(b'{"tampered":true}')
app2 = create_app(data_dir=data_dir, downstream_dir=down_dir)
check("6a 下游凭据被改 → 按登记重建",
      sha(open(cred_path, "rb").read()) == pv_cur["credential_sha256"])
os.unlink(cred_path)
app3 = create_app(data_dir=data_dir, downstream_dir=down_dir)
check("6b 下游凭据缺失 → 按登记重建",
      sha(open(cred_path, "rb").read()) == pv_cur["credential_sha256"])
check("重建后的凭据仍可下载且与登记一致",
      app3.test_client().get(f"/evidence/{cur}/credential.json").data
      == pv_cur["credential_text"].encode())

snap_dir = os.path.join(data_dir, "versions", f"v{cur}")
with open(os.path.join(snap_dir, "published_results.csv"), "wb") as fh:
    fh.write(b"corrupted\n")
os.unlink(os.path.join(snap_dir, CREDENTIAL_FILENAME))
app4 = create_app(data_dir=data_dir, downstream_dir=down_dir)
check("6c 历史快照 CSV 被改 → 按登记重建",
      open(os.path.join(snap_dir, "published_results.csv"), "rb").read()
      == pv_cur["csv_content"].encode())
check("6d 历史快照凭据缺失 → 按登记重建",
      sha(open(os.path.join(snap_dir, CREDENTIAL_FILENAME), "rb").read())
      == pv_cur["credential_sha256"])

rogue = os.path.join(data_dir, "versions", "v999")
os.makedirs(rogue, exist_ok=True)
with open(os.path.join(rogue, "published_results.csv"), "wb") as fh:
    fh.write(b"x")
app5 = create_app(data_dir=data_dir, downstream_dir=down_dir)
check("6e 未登记的快照目录被隔离（不冒充历史版本）",
      not os.path.exists(rogue)
      and any("version-v999" in n
              for n in os.listdir(os.path.join(data_dir, "quarantine"))))
check("6f 版本链仍完整：每版前驱 = 上一版摘要",
      all(
          (st.published_version(v) is None)
          or (v == 3 and st.published_version(v)["prev_credential_sha256"] is None)
          or st.published_version(v)["prev_credential_sha256"]
          == st.published_version(v - 1)["credential_sha256"]
          for v in app5.storage.all_version_numbers()
      ))
check("6g 所有凭据仍只指向存在的版本数据",
      all(app5.storage.published_version(v)["csv_content"]
          == app5.storage.version_csv_text(v)
          for v in app5.storage.all_version_numbers()))

# 旧版无凭据，恢复不得给它造凭据
app5.storage._atomic_write_bytes(
    os.path.join(down_dir, CREDENTIAL_FILENAME),
    b'{"fake":1}', ".tmp-credential-",
)
with app5.storage._connect() as conn:
    conn.execute(
        "UPDATE evidence_activation SET version = ?",
        (app5.storage.current_registry()["current_version"] + 1,),
    )
app6 = create_app(data_dir=data_dir, downstream_dir=down_dir)
check("6h 当前版本回到启用前状态时，遗留凭据被隔离",
      not os.path.exists(os.path.join(down_dir, CREDENTIAL_FILENAME))
      and any(n.endswith(CREDENTIAL_FILENAME)
              for n in os.listdir(os.path.join(data_dir, "quarantine"))))

# ---------------- 7b. 发布中途失败：回滚文件、不生成凭据 ----------------
print("== 7b. 发布中途失败的回滚 ==")
tmp2 = tempfile.mkdtemp(prefix="wq-evidence-fail-")
d2 = os.path.join(tmp2, "data")
o2 = os.path.join(tmp2, "downstream")
app_f = create_app(data_dir=d2, downstream_dir=o2)
cf = app_f.test_client()
publish(cf, "batch_v1.csv", "BASE")
v_base = app_f.storage.current_registry()["current_version"]
base_csv = open(os.path.join(o2, LIVE_FILENAME), "rb").read()
base_cred = open(os.path.join(o2, CREDENTIAL_FILENAME), "rb").read()
base_sha = app_f.storage.published_version(v_base)["credential_sha256"]

original_log = app_f.storage._log


def boom(conn, kind, detail):
    if kind == "publish":
        raise RuntimeError("simulated crash before commit")
    return original_log(conn, kind, detail)


app_f.storage._log = boom
resp = publish(cf, "batch_v2_revision.csv", "FAIL-ME")
app_f.storage._log = original_log
check("发布中途异常时请求不误报成功", resp.status_code == 500)
check("异常后版本号未前进",
      app_f.storage.current_registry()["current_version"] == v_base)
check("异常后不生成新版本凭据记录",
      app_f.storage.published_version(v_base + 1) is None)
check("异常后下游 CSV 已回滚为旧版",
      open(os.path.join(o2, LIVE_FILENAME), "rb").read() == base_csv)
check("异常后下游凭据已回滚为旧版",
      open(os.path.join(o2, CREDENTIAL_FILENAME), "rb").read() == base_cred)
check("异常后下游凭据仍与登记一致",
      sha(open(os.path.join(o2, CREDENTIAL_FILENAME), "rb").read()) == base_sha)
check("异常后不留未提交的版本快照目录",
      not os.path.exists(os.path.join(d2, "versions", f"v{v_base + 1}")))
# 恢复后仍可正常发布，链条继续接在 v_base 之后
resp = publish(cf, "batch_v2_revision.csv", "AFTER-FAIL")
v_new = app_f.storage.current_registry()["current_version"]
cred_new = app_f.storage.version_credential(v_new)[0]
check("失败后重新发布成功且前驱仍为旧版凭据",
      resp.status_code == 302 and v_new == v_base + 1
      and cred_new["prev_credential_sha256"] == base_sha)
shutil.rmtree(tmp2, ignore_errors=True)

# ---------------- 7. 凭据字段结构 ----------------
print("== 7. 凭据结构 ==")
payload, errs = parse_credential(raw4)
check("凭据字段齐全", errs == [] and payload["credential_type"])
bad_payload, errs = parse_credential(b'{"version": 4}')
check("缺字段凭据被判非法",
      any("batch_no" in e for e in errs) and any("csv_sha256" in e for e in errs))

# ---------------- 8. docker compose ----------------
print("== 8. docker compose ==")
compose_path = os.path.join(ROOT, "docker-compose.yml")
check("docker-compose.yml 存在", os.path.exists(compose_path))
try:
    import yaml
except ImportError:
    yaml = None
if yaml is not None:
    with open(compose_path) as fh:
        compose = yaml.safe_load(fh)
    svc = compose["services"]["wq-publish"]
    check("compose 含构建、端口、两份持久卷与单实例约束",
          svc.get("build") and "5000:5000" in svc.get("ports", [])
          and len(svc.get("volumes", [])) == 2)
else:
    text = open(compose_path).read()
    check("compose 文本含服务/端口/卷（未装 PyYAML，仅检查文本）",
          "5000:5000" in text and "wq-data" in text and "replicas: 1" in text)
check("Dockerfile 存在且使用 serve.py",
      os.path.exists(os.path.join(ROOT, "Dockerfile"))
      and "serve.py" in open(os.path.join(ROOT, "Dockerfile")).read())

shutil.rmtree(tmp, ignore_errors=True)
print(f"\n结果：{PASS} 通过，{FAIL} 失败")
sys.exit(1 if FAIL else 0)
