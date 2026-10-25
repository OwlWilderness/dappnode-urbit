"""File-only integrity checks. Does not build, fetch or execute upstream code."""
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import tarfile

O = Path(__file__).resolve().parent
R = O.parents[2]

def digest(data):
    return hashlib.sha256(data).hexdigest()

def gitblob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()

def load(path):
    return json.loads(path.read_text())

def check_ref(record):
    path = R / record["path"]
    assert path.is_file() and not path.is_symlink(), str(path)
    data = path.read_bytes()
    assert digest(data) == record["sha256"], record["path"]
    if "bytes" in record:
        assert len(data) == record["bytes"], record["path"]

files = load(O / "FILES.json")
for record in files["files"]:
    check_ref(record)
actual = {str(p.relative_to(R)) for p in O.rglob("*") if p.is_file()}
assert actual - {str((O / "FILES.json").relative_to(R)), str((O / "verification.json").relative_to(R))} == {r["path"] for r in files["files"] if r["path"].startswith("THIRD_PARTY/vere/followup/")}

manifest = load(R / "THIRD_PARTY/source-delivery.json")
assert manifest["release_blocked"] and not manifest["final_notice_image_built"]
assert not manifest["written_offer_issued"]
assert not manifest["complete_corresponding_source_delivery"]
assert not manifest["legal_clearance"] and not manifest["binary_membership_verified"]
assert manifest["refresh_after_parent_integration"]["required"]
assert not manifest["refresh_after_parent_integration"]["final_dockerfile_or_context_hash_frozen"]
for field in ("prepared_materials", "input_locks", "notices"):
    for record in manifest[field]:
        check_ref(record)

old = load(R / "THIRD_PARTY/vere/inventory.json")
for record in old["files"]:
    check_ref({**record, "path": "THIRD_PARTY/vere/" + record["path"]})

source = load(O / "source-inputs.json")
vt = load(R / "THIRD_PARTY/vere/evidence/vere-tree.json")
blobs = {e["path"]: e for e in vt["tree"] if e["type"] == "blob"}
for record in source["build_and_workflow_files"] + source["patch_replacement_files"]:
    check_ref(record)
    assert gitblob((R / record["path"]).read_bytes()) == record["git_blob"] == blobs[record["upstream_path"]]["sha"]

index = load(O / "archive-members.json")
check_ref(index["archive"])
with tarfile.open(R / index["archive"]["path"]) as tf:
    extracted = {m.name.split("/", 1)[1]: tf.extractfile(m).read() for m in tf if m.isfile()}
assert set(extracted) == set(blobs) == {e["path"] for e in index["files"]}
for entry in index["files"]:
    b = extracted[entry["path"]]
    assert digest(b) == entry["sha256"] and len(b) == entry["bytes"]
    assert gitblob(b) == entry["git_blob"] == blobs[entry["path"]]["sha"]

wrapper = load(O / "wrapper-source-lock.json")
assert wrapper["refresh_required"] and not wrapper["release_binding_accepted"]
check_ref(wrapper["source_archive"])
with tarfile.open(R / wrapper["source_archive"]["path"]) as tf:
    snap = {m.name.split("/", 1)[1]: tf.extractfile(m).read() for m in tf if m.isfile()}
assert set(snap) == {e["path"] for e in wrapper["source_files"]}
for entry in wrapper["source_files"]:
    assert digest(snap[entry["path"]]) == entry["sha256"]
# These are historical snapshot hashes, deliberately not final current-file locks.
changed_snapshot_paths = [e["path"] for e in wrapper["source_files"] if not (R/e["path"]).exists() or digest((R/e["path"]).read_bytes()) != e["sha256"]]

retrievals = load(O / "retrievals.json")
for rec in retrievals["retrievals"]:
    check_ref(rec)
for name in ("urcrypt", "h2o"):
    tree = {e["path"]: e for e in load(O / ("evidence/" + name + "-tree.json"))["tree"] if e["type"] == "blob"}
    for p in (O / "notices" / name).rglob("*.txt"):
        upstream_path = str(p.relative_to(O / "notices" / name))[:-4]
        assert gitblob(p.read_bytes()) == tree[upstream_path]["sha"]

comparison = load(O / "blake3-comparison.json")
assert len(comparison["selected_files"]) == 9
assert sum(e["identical"] for e in comparison["selected_files"]) == 6
for entry in comparison["selected_files"]:
    assert entry["identical"] == (entry["vendored_git_blob"] == entry["upstream_git_blob"])
    if not entry["identical"]:
        check_ref(entry["diff"])
assert '#include "khash.h"' in (O/"notices/h2o/lib/common/cache.c.txt").read_text()
assert '#include "curve25519.tweetnacl.c"' in (O/"notices/h2o/deps/picotls/deps/cifra/src/curve25519.c.txt").read_text()
assert 'Permission to use, copy, modify, and distribute' in (O/"notices/h2o/deps/picotls/lib/asn1.c.txt").read_text()
assert 'free for all purposes' in (O/"notices/urcrypt/ed25519/src/sha512.c.txt").read_text()
app = load(O/"applicability.json")
assert len(app["records"]) == app["record_count"] == 13
for entry in app["records"]:
    assert not entry["binary_presence_verified"]
    assert (R/entry["adapter"]["path"]).is_file()
    for record in entry["evidence"]:
        check_ref(record)
for record in app["notice_sources"]:
    check_ref(record)
assert len(app["notice_sources"]) == app["supplementary_notice_blocks"] == (O/"NOTICES.txt").read_text().count("SOURCE: ")

dependencies = load(O / "dependency-lock.json")
assert dependencies["declarations"] == old["declarations"]
assert len(dependencies["components"]) == 30
declared_urls = {e["value"] for e in dependencies["declarations"] if e["kind"] == "url"}
declared_urls.update(c["declared_source_url"] for c in dependencies["components"] if c.get("declared_source_url") and c["component"] == "zlib")
assert len(declared_urls) == 26
json_files = [p for p in O.rglob("*.json") if p.name != "verification.json"] + [R / "THIRD_PARTY/source-delivery.json"]
for p in json_files:
    load(p)
links = 0
for path in [O / "README.md", R / "THIRD_PARTY/SOURCE_DELIVERY.md"]:
    for target in re.findall(r'\[[^\]]+\]\(([^)]+)\)', path.read_text()):
        if "://" in target or target.startswith("#"):
            continue
        assert (path.parent / target.split("#", 1)[0]).exists(), (str(path), target)
        links += 1
result = {
    "schema_version": 1,
    "status": "PASS_FILE_INTEGRITY_NOT_DELIVERY_COMPLETENESS",
    "owned_file_hash_checks": len(files["files"]),
    "retained_evidence_hash_checks": len(old["files"]),
    "upstream_build_patch_blob_checks": len(source["build_and_workflow_files"]) + len(source["patch_replacement_files"]),
    "vere_archive_blob_checks": len(index["files"]),
    "wrapper_archive_file_checks": len(wrapper["source_files"]),
    "retrieval_hash_checks": len(retrievals["retrievals"]),
    "json_files_parsed_excluding_result": len(json_files),
    "local_documentation_links_checked": links,
    "applicability_records": app["record_count"],
    "supplementary_notice_blocks": app["supplementary_notice_blocks"],
    "historical_wrapper_snapshot_changed_paths_observed": changed_snapshot_paths,
    "wrapper_refresh_required": True,
    "release_blocked": True,
    "final_image_built": False,
    "written_offer_issued": False,
    "complete_corresponding_source_delivery": False,
    "legal_clearance": False,
    "build_runtime_docker_or_network_performed": False,
}
if "--write-result" in sys.argv:
    (O / "verification.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result, indent=2))
