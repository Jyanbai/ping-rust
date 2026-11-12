"""合并门禁回归；仅由 GitHub Actions 执行。"""
import copy
import unittest

from pr_merge_gate import evaluate, review_verdict


class GateTests(unittest.TestCase):
    def setUp(self):
        self.sha = "a" * 40
        self.policy = {"ci.yml": {"unit": ["Test"]}}
        self.run = {"id": 1, "run_attempt": 1, "head_sha": self.sha,
                    "event": "pull_request", "path": ".github/workflows/ci.yml",
                    "status": "completed", "conclusion": "success"}
        self.job = {"name": "unit", "status": "completed", "conclusion": "success",
                    "steps": [{"name": "Test", "status": "completed", "conclusion": "success"}]}

    def check(self, runs=None, jobs=None):
        return evaluate(self.sha, self.policy, runs if runs is not None else [self.run],
                        jobs if jobs is not None else {1: [self.job]})

    def test_success(self):
        self.assertEqual(self.check(), [])

    def test_missing_or_old_sha(self):
        self.assertTrue(self.check([]))
        self.run["head_sha"] = "b" * 40
        self.assertTrue(self.check())

    def test_every_non_success_blocks_at_run_job_and_step(self):
        for result in ["failure", "cancelled", "timed_out", "skipped", "neutral", None, "action_required", "stale"]:
            for target in [self.run, self.job, self.job["steps"][0]]:
                with self.subTest(result=result, target=target):
                    target["conclusion"] = result
                    self.assertTrue(self.check())
                    target["conclusion"] = "success"

    def test_in_progress_blocks(self):
        for target in [self.run, self.job, self.job["steps"][0]]:
            target["status"] = "in_progress"
            self.assertTrue(self.check())
            target["status"] = "completed"

    def test_latest_run_wins(self):
        newer = dict(self.run, id=2, conclusion="failure")
        self.assertTrue(self.check([self.run, newer], {1: [self.job], 2: [self.job]}))

    def test_missing_job_step_or_empty_jobs(self):
        self.assertTrue(self.check(jobs={1: []}))
        self.job["steps"] = []
        self.assertTrue(self.check())
        self.job["name"] = "impostor"
        self.assertTrue(self.check())

    def test_wrong_workflow_or_event_is_not_evidence(self):
        for key, value in [("path", ".github/workflows/fake.yml"), ("event", "push"), ("event", "workflow_dispatch")]:
            run = dict(self.run, **{key: value})
            self.assertTrue(self.check([run]))

    def test_duplicate_job_or_step_blocks(self):
        self.assertTrue(self.check(jobs={1: [self.job, copy.deepcopy(self.job)]}))
        self.job["steps"] *= 2
        self.assertTrue(self.check())

    def test_review_attestation(self):
        base = "b" * 40
        marker = f"<!-- codex-review-verdict sha={self.sha} base={base} findings=0 run=99 attempt=1 -->"
        comment = {"user": {"login": "github-actions[bot]", "type": "Bot"}, "body": marker}
        run = dict(self.run, id=99, path=".github/workflows/codex-code-review.yml", event="workflow_run")
        job = dict(self.job, name="review", steps=[
            {"name": n, "status": "completed", "conclusion": "success"} for n in
            ["Verify read-only sandbox", "Run Codex review", "Render review", "Publish review"]])
        self.assertEqual(review_verdict(self.sha, base, [comment], {99: run}, {99: [job]}), [])
        for bad in [marker.replace("findings=0", "findings=1"), marker.replace(base, "c" * 40), marker.replace(self.sha, "c" * 40), marker.replace("attempt=1", "attempt=2")]:
            self.assertTrue(review_verdict(self.sha, base, [dict(comment, body=bad)], {99: run}, {99: [job]}))
        self.assertTrue(review_verdict(self.sha, base, [dict(comment, user={"login": "outsider", "type": "User"})], {99: run}, {99: [job]}))
        job["steps"][-1]["conclusion"] = "skipped"
        self.assertTrue(review_verdict(self.sha, base, [comment], {99: run}, {99: [job]}))


if __name__ == "__main__":
    unittest.main()

