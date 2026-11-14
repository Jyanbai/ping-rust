"""Strict Release gate positive and negative regression cases (GitHub Actions only)."""
import copy
import io
import os
import subprocess
from pathlib import Path
import tarfile
import tempfile
import unittest
from release_gate import GateError, Pending, TARGETS, verify_artifacts, verify_checks, verify_version

SHA = "a"*40
MANIFEST = '[package]\nname = "ping-rust"\nversion = "0.3.0"\n'
LOCK = 'version = 4\n[[package]]\nname = "ping-rust"\nversion = "0.3.0"\n'


class API:
    def __init__(self):
        self.policy = {"ci.yml":{"unit":["Execute tests"]}}
        self.run = dict(id=15,run_attempt=1,head_sha=SHA,event="push",
                        path=".github/workflows/ci.yml",status="completed",conclusion="success")
        self.job = dict(name="unit",status="completed",conclusion="success",steps=[
            dict(name="Execute tests",status="completed",conclusion="success")])
        self.runs = [self.run]
        self.jobs = {(15,1):[self.job]}
        self.details = {}

    def get(self,path):
        if path.startswith("actions/runs/"):
            ident=int(path.split("/")[2])
            return copy.deepcopy(self.details.get(ident, next(x for x in self.runs if x["id"]==ident)))
        raise AssertionError(path)

    def pages(self,path,key):
        if path.startswith("actions/runs?"):
            return copy.deepcopy(self.runs)
        parts=path.split("/")
        if parts[:2]==["actions","runs"] and parts[3]=="attempts":
            return copy.deepcopy(self.jobs[(int(parts[2]),int(parts[4]))])
        raise AssertionError(path)

    def check(self):
        return verify_checks(self,SHA,self.policy)


class Tests(unittest.TestCase):
    def test_rollback_reconciles_public_draft_and_unknown_outcomes(self):
        root=Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as temp:
            directory=Path(temp)
            gh=directory/"gh"
            gh.write_text('#!/bin/sh\nif [ "$2" = view ]; then\n'
                          '  [ "$MOCK_DRAFT" != lookup-error ] || exit 1\n'
                          '  printf "%s\\n" "$MOCK_DRAFT"\n'
                          'else\n  printf "%s\\n" "$*" >> "$MOCK_EDITS"\nfi\n')
            gh.chmod(0o755)
            for draft,success,edited in [("false",True,True),("true",True,False),
                                         ("lookup-error",False,False),("unknown",False,False)]:
                edits=directory/"edits"
                edits.unlink(missing_ok=True)
                env=dict(os.environ,PATH=f"{directory}:{os.environ['PATH']}",
                         MOCK_DRAFT=draft,MOCK_EDITS=str(edits),GITHUB_REF_NAME="v0.3.0")
                result=subprocess.run(["bash",str(root/"scripts/ci/release_rollback.sh")],
                                      env=env,capture_output=True)
                with self.subTest(draft=draft):
                    self.assertEqual(result.returncode==0,success)
                    self.assertEqual(edits.exists(),edited)
                    if edited:self.assertIn("--draft=true",edits.read_text())
        workflow=(root/".github/workflows/release.yml").read_text()
        self.assertLess(workflow.index("echo 'attempted=true'"),
                        workflow.index('gh release edit "${GITHUB_REF_NAME}" --draft=false'))
        self.assertIn("always() && steps.publish.outputs.attempted == 'true' && steps.accepted.outputs.verified != 'true'",workflow)

    def test_version_and_manifest_lock(self):
        self.assertEqual(verify_version("v0.3.0",MANIFEST,LOCK),"0.3.0")
        for tag,manifest,lock in [
            ("v0.3.1",MANIFEST,LOCK),("bad",MANIFEST,LOCK),
            ("v01.3.0",MANIFEST,LOCK),("v0.3.0-rc",MANIFEST,LOCK),
            ("v0.3.0",MANIFEST.replace("0.3.0","0.2.9"),LOCK),
            ("v0.3.0",MANIFEST,LOCK.replace("0.3.0","0.2.9"))]:
            with self.subTest(tag=tag):
                with self.assertRaises(GateError):
                    verify_version(tag,manifest,lock)

    def test_exact_sha_and_latest_run(self):
        api=API()
        self.assertEqual(api.check(),{"ci.yml":"15/attempt-1"})
        api.run["head_sha"]="b"*40
        with self.assertRaises(Pending):api.check()
        api.run["head_sha"]=SHA
        api.run["event"]="workflow_dispatch"
        with self.assertRaises(Pending):api.check()
        api.run["event"]="push"
        api.runs.append(dict(api.run,id=16,conclusion="failure"))
        with self.assertRaises(GateError):api.check()

    def test_failed_cancelled_skipped_timed_out_missing(self):
        for val in ["failure","cancelled","timed_out","skipped","neutral",None]:
            for key in ["run","job","step"]:
                with self.subTest(val=val,key=key):
                    api=API()
                    target={"run":api.run,"job":api.job,"step":api.job["steps"][0]}[key]
                    target["conclusion"]=val
                    with self.assertRaises(GateError):api.check()
        for key in ["run","job","step"]:
            api=API()
            target={"run":api.run,"job":api.job,"step":api.job["steps"][0]}[key]
            target["status"]="in_progress"
            with self.assertRaises((GateError,Pending)):api.check()
        for mode in ["no-jobs","no-step","duplicate-step","extra-failed"]:
            api=API()
            if mode=="no-jobs":api.jobs[(15,1)]=[]
            elif mode=="no-step":api.job["steps"]=[]
            elif mode=="duplicate-step":api.job["steps"].append(copy.deepcopy(api.job["steps"][0]))
            else:api.jobs[(15,1)].append(dict(api.job,name="extra",conclusion="failure"))
            with self.subTest(mode=mode):
                with self.assertRaises(GateError):api.check()

    def test_step_alias_requires_exactly_one_successful_listed_name(self):
        old,new="Prepare one managed node","Prepare two managed nodes"
        for names,conclusion,ok in [((old,),"success",True),((new,),"success",True),
                                    ((old,new),"success",False),((),"success",False),
                                    (("Prepare three managed nodes",),"success",False),
                                    ((new,),"skipped",False)]:
            api=API()
            api.policy={"ci.yml":{"unit":[{"any_of":[old,new]}]}}
            api.job["steps"]=[dict(name=n,status="completed",conclusion=conclusion) for n in names]
            with self.subTest(names=names,conclusion=conclusion):
                if ok:self.assertEqual(api.check(),{"ci.yml":"15/attempt-1"})
                else:
                    with self.assertRaises(GateError):api.check()
        for bad in [{"any_of":[old]},{"any_of":[old,old]},{"any_of":old},{"all_of":[old,new]},[old,new]]:
            api=API()
            api.policy={"ci.yml":{"unit":[bad]}}
            api.job["steps"]=[dict(name=old,status="completed",conclusion="success")]
            with self.subTest(bad=bad):
                with self.assertRaises(GateError):api.check()

    def test_attempt_merge_and_race_protection(self):
        api=API()
        api.policy["ci.yml"]["extra"]=["Execute tests"]
        api.run["run_attempt"]=2
        api.jobs[(15,1)].append(dict(api.job,name="extra",conclusion="failure"))
        api.jobs[(15,2)]=[dict(api.job,name="extra")]
        self.assertEqual(api.check(),{"ci.yml":"15/attempt-2"})
        api.jobs[(15,2)][0]["conclusion"]="skipped"
        with self.assertRaises(GateError):api.check()
        api=API()
        api.details[15]=dict(api.run,run_attempt=2)
        with self.assertRaises(GateError):api.check()

    def test_asset_integrity_and_architecture(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            for target,machine in TARGETS.items():
                blob=bytearray(64)
                blob[:6]=b"\x7fELF\x02\x01"
                blob[18:20]=machine.to_bytes(2,"little")
                with tarfile.open(root / f"ping-rust-{target}.tar.gz","w:gz") as tar:
                    info=tarfile.TarInfo("ping-rust")
                    info.mode=0o755
                    info.size=len(blob)
                    tar.addfile(info,io.BytesIO(blob))
            self.assertEqual(len(verify_artifacts(root).splitlines()),2)
            (root/"SHA256SUMS").unlink()
            (root/"unexpected").write_text("extra")
            with self.assertRaises(GateError):verify_artifacts(root)
            (root/"unexpected").unlink()
            arm=root/"ping-rust-aarch64-unknown-linux-musl.tar.gz"
            arm.write_bytes((root/"ping-rust-x86_64-unknown-linux-musl.tar.gz").read_bytes())
            with self.assertRaises(GateError):verify_artifacts(root)
            arm.unlink()
            with self.assertRaises(GateError):verify_artifacts(root)

    def test_workflow_must_not_clobber_or_skip_release_gate(self):
        path=Path(__file__).resolve().parents[2]/".github/workflows/release.yml"
        text=path.read_text()
        self.assertNotIn("--clobber",text)
        for field in ("verify-required-checks","Verify release assets and generate SHA256SUMS",
                      "Verify public download integrity","Rollback public Release to draft on failure",
                      "gh release create","--draft"):
            self.assertIn(field,text)


if __name__=="__main__":
    unittest.main()
