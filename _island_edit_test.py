"""Throwaway functional test for POST /island/edit.

Spins up a temp project (tiny binary + yaml with two islands), points the
server STATE at it, and drives the endpoint through the Flask test client.
Run: python _island_edit_test.py
"""
import json
import tempfile
from pathlib import Path

import eval_server as es

VRAM = 0x06000000


def make_project(tmp, islands_yaml, subsegs_yaml=""):
    root = Path(tmp)
    (root / "config").mkdir(parents=True, exist_ok=True)
    (root / "build").mkdir(parents=True, exist_ok=True)
    binpath = root / "build" / "FOO.BIN"
    binpath.write_bytes(b"\x00" * 0x400)
    yaml_path = root / "config" / "FOO.yaml"
    yaml_path.write_text(
        "options:\n"
        "  target_path: build/FOO.BIN\n"
        f"  vram: 0x{VRAM:08X}\n"
        f"{islands_yaml}"
        "subsegments:" + (subsegs_yaml or " []\n")
    )
    es.STATE["yaml_path"] = yaml_path
    es.STATE["project_root"] = root
    es.STATE["session_path"] = root / "config" / "FOO.session.json"
    es.STATE["model"] = None  # force rebuild per project
    return yaml_path


def read_islands(yaml_path):
    import yaml
    return (yaml.safe_load(yaml_path.read_text()).get("islands") or [])


def post(client, path, body):
    r = client.post(path, data=json.dumps(body), content_type="application/json")
    return r.status_code, r.get_json()


TWO_ISLANDS = (
    "islands:\n"
    "  - seed: 0x06000100\n"
    "    end:  0x06000200\n"
    "  - seed: 0x06000300\n"
    "    end:  0x06000380\n"
)

passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  PASS  {name}")
    else:
        failed += 1
        print(f"  FAIL  {name}  {detail}")


with tempfile.TemporaryDirectory() as tmp:
    client = es.app.test_client()

    # --- end-only: raise the first island's end -------------------------
    yp = make_project(tmp, TWO_ISLANDS)
    code, body = post(client, "/island/edit", {"seed": "0x06000100", "end": "0x06000250"})
    isl = read_islands(yp)
    check("raise end -> 200 ok", code == 200 and body.get("ok"), body)
    check("raise end -> yaml updated", isl[0]["seed"] == 0x06000100 and isl[0]["end"] == 0x06000250, isl)
    check("raise end -> order/other island preserved",
          [i["seed"] for i in isl] == [0x06000100, 0x06000300] and isl[1]["end"] == 0x06000380, isl)

    # --- end -> null makes the window open-ended ------------------------
    yp = make_project(tmp, TWO_ISLANDS)
    code, body = post(client, "/island/edit", {"seed": "0x06000300", "end": None})
    isl = read_islands(yp)
    check("end:null -> 200 ok", code == 200 and body.get("ok") and body.get("end") is None, body)
    check("end:null -> island has no end key", isl[1]["seed"] == 0x06000300 and isl[1].get("end") is None, isl)

    # --- omitting end leaves it unchanged (move seed only) --------------
    yp = make_project(tmp, TWO_ISLANDS)
    code, body = post(client, "/island/edit", {"seed": "0x06000300", "new_seed": "0x06000320"})
    isl = read_islands(yp)
    check("move seed -> 200 ok", code == 200 and body.get("ok"), body)
    check("move seed -> seed changed, end preserved",
          isl[1]["seed"] == 0x06000320 and isl[1]["end"] == 0x06000380, isl)
    check("move seed -> declaration order preserved", [i["seed"] for i in isl] == [0x06000100, 0x06000320], isl)

    # --- validation errors ---------------------------------------------
    yp = make_project(tmp, TWO_ISLANDS)
    check("missing seed -> 400", post(client, "/island/edit", {"end": "0x06000250"})[0] == 400)
    check("unknown seed -> 400", post(client, "/island/edit", {"seed": "0x06009999", "end": "0x0600A000"})[0] == 400)
    check("nothing to edit -> 400", post(client, "/island/edit", {"seed": "0x06000100"})[0] == 400)
    check("odd new_seed -> 400", post(client, "/island/edit", {"seed": "0x06000100", "new_seed": "0x06000101"})[0] == 400)
    check("new_seed outside binary -> 400", post(client, "/island/edit", {"seed": "0x06000100", "new_seed": "0x07000000"})[0] == 400)
    check("new_seed == other island seed -> 400", post(client, "/island/edit", {"seed": "0x06000100", "new_seed": "0x06000300"})[0] == 400)
    check("end before seed -> 400", post(client, "/island/edit", {"seed": "0x06000100", "end": "0x06000050"})[0] == 400)
    # yaml unchanged after all the rejects above
    check("rejects left yaml intact", [i["seed"] for i in read_islands(yp)] == [0x06000100, 0x06000300], read_islands(yp))

    # --- corruption guard: moving a seed above its own stamp orphans it -
    subsegs = (
        "\n"
        "  - start: 0x06000100\n"
        "    end:   0x0600013F\n"
        "    type:  code\n"
        "    file:  fun_06000100\n"
    )
    yp = make_project(tmp, TWO_ISLANDS, subsegs)
    code, body = post(client, "/island/edit", {"seed": "0x06000100", "new_seed": "0x06000180"})
    check("orphaning seed move -> 400", code == 400 and not body.get("ok"), body)
    check("orphaning seed move -> yaml intact",
          [i["seed"] for i in read_islands(yp)] == [0x06000100, 0x06000300], read_islands(yp))
    # end-raise on a seeded+stamped island is still fine (soft end, no guard)
    code, body = post(client, "/island/edit", {"seed": "0x06000100", "end": "0x06000280"})
    check("end-raise with stamps -> 200 ok", code == 200 and body.get("ok"), body)

print(f"\n{passed} passed, {failed} failed")
raise SystemExit(1 if failed else 0)
