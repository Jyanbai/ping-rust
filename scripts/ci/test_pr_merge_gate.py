"""合并门禁回归；仅由 GitHub Actions 执行。"""
import copy
import json
from pathlib import Path
import unittest

from pr_merge_gate import evaluate, review_verdict, inspect_pr, latest_review, REVIEW_STEPS


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
        run = dict(self.run, id=99, path=".github/workflows/codex-code-review.yml", event="workflow_run", head_branch="main")
        run['attestation'] = {'head': self.sha, 'base': base, 'findings': 0, 'run': 99, 'attempt': 1}
        job = dict(self.job, name="review", steps=[
            {"name": n, "status": "completed", "conclusion": "success"} for n in
            REVIEW_STEPS])
        self.assertEqual(review_verdict(self.sha, base, [comment], {99: run}, {99: [job]}), [])
        run['head_branch'] = 'untrusted-pr'
        self.assertTrue(review_verdict(self.sha, base, [comment], {99: run}, {99: [job]}))
        run['head_branch'] = 'main'
        for bad in [marker.replace("findings=0", "findings=1"), marker.replace(base, "c" * 40), marker.replace(self.sha, "c" * 40), marker.replace("attempt=1", "attempt=2")]:
            self.assertTrue(review_verdict(self.sha, base, [dict(comment, body=bad)], {99: run}, {99: [job]}))
        self.assertTrue(review_verdict(self.sha, base, [dict(comment, user={"login": "outsider", "type": "User"})], {99: run}, {99: [job]}))
        # 其他 bot 评论伪造 marker，引用旧成功 Review 也不能复用旧 head 的证明。
        run['attestation']['head'] = 'c' * 40
        self.assertTrue(review_verdict(self.sha, base, [comment], {99: run}, {99: [job]}))
        run['attestation']['head'] = self.sha
        job["steps"][-1]["conclusion"] = "skipped"
        self.assertTrue(review_verdict(self.sha, base, [comment], {99: run}, {99: [job]}))

    def test_real_policy_all_requirements_have_positive_and_negative_coverage(self):
        policy = json.loads(Path(__file__).with_name('pr_merge_gate_policy.json').read_text())
        self.assertEqual(set(policy), {'ci.yml', 'shoes-schema.yml', 'backward-compat.yml',
            'vless-encryption.yml', 'chain-systemd.yml', 'legacy-upgrade.yml',
            'ubuntu-acceptance.yml', 'performance-baseline.yml', 'security-audit.yml',
            'pr-merge-gate-tests.yml'})
        runs, jobs = [], {}
        for rid, (workflow, expected) in enumerate(policy.items(), 1):
            runs.append(dict(self.run, id=rid, path=f'.github/workflows/{workflow}'))
            jobs[rid] = [dict(self.job, name=name, steps=[dict(self.job['steps'][0], name=s) for s in steps])
                         for name, steps in expected.items()]
        self.assertEqual(evaluate(self.sha, policy, runs, jobs), [])
        for run in runs:
            self.assertTrue(evaluate(self.sha, policy, [r for r in runs if r is not run], jobs))
        for suite in jobs.values():
            for job in suite:
                for step in job['steps']:
                    step['conclusion'] = 'skipped'
                    self.assertTrue(evaluate(self.sha, policy, runs, jobs), step['name'])
                    step['conclusion'] = 'success'

    def test_collector_fails_closed_on_api_error_or_head_change(self):
        outer = self

        class FakeAPI:
            def __init__(self, fail=False):
                self.statuses = []
                self.reads = 0
                self.fail = fail

            def request(self, path):
                if self.fail:
                    # 首次读取 PR 成功，读取证据时失败。
                    if self.reads:
                        raise RuntimeError('API unavailable')
                self.reads += 1
                return {'state': 'open', 'base': {'sha': 'b' * 40, 'ref': 'main'},
                        'head': {'sha': outer.sha if self.reads == 1 else 'c' * 40}}

            def pages(self, path, key=None):
                if self.fail:
                    raise RuntimeError('API unavailable')
                return []

            def status(self, sha, state, description):
                self.statuses.append((sha, state))

        api = FakeAPI()
        self.assertTrue(inspect_pr(api, 7, self.policy))
        self.assertEqual(api.statuses, [(self.sha, 'pending'), (self.sha, 'failure')])
        api = FakeAPI(fail=True)
        with self.assertRaises(RuntimeError):
            inspect_pr(api, 7, self.policy)
        self.assertEqual(api.statuses[-1], (self.sha, 'failure'))

    def test_collector_ignores_optional_and_superseded_review_runs(self):
        outer = self
        base = 'b' * 40
        comment = {'user': {'login': 'github-actions[bot]', 'type': 'Bot'},
                   'body': f'<!-- codex-review-verdict sha={self.sha} base={base} findings=0 run=99 attempt=1 -->'}
        run = dict(self.run, pull_requests=[{'number': 7, 'head': {'sha': self.sha}, 'base': {'sha': base}}])
        optional = dict(run, id=2, path='.github/workflows/reality-sni-candidates.yml', conclusion='failure')
        review = dict(self.run, id=99, path='.github/workflows/codex-code-review.yml', event='workflow_run', head_branch='main',
                      display_title=f'Codex Review pr=0 sha={self.sha}')
        review_job = dict(self.job, name='review', steps=[dict(self.job['steps'][0], name=n) for n in REVIEW_STEPS])

        class FakeAPI:
            def __init__(self):
                self.statuses = []
                self.calls = []

            def request(self, path):
                self.calls.append(path)
                if path.startswith('pulls/'):
                    return {'state': 'open', 'head': {'sha': outer.sha}, 'base': {'sha': base, 'ref': 'main'}}
                return copy.deepcopy({'actions/runs/1': run, 'actions/runs/99': review}[path])

            def pages(self, path, key=None):
                self.calls.append(path)
                if path.startswith('actions/workflows/'):
                    return [review]
                if path.startswith('actions/runs?'):
                    return [run, optional]
                if path.endswith('/comments'):
                    old = dict(comment, body=comment['body'].replace('run=99', 'run=98'))
                    return [old, comment]
                return {'actions/runs/1/attempts/1/jobs': [outer.job],
                        'actions/runs/99/attempts/1/jobs': [review_job]}[path]

            def attestation(self, selected):
                return {'head': outer.sha, 'base': base, 'findings': 0, 'run': 99, 'attempt': 1}

            def status(self, sha, state, description):
                self.statuses.append(state)

        api = FakeAPI()
        self.assertEqual(inspect_pr(api, 7, self.policy), [])
        self.assertEqual(api.statuses, ['pending', 'success'])
        self.assertNotIn('actions/runs/2', api.calls)
        self.assertNotIn('actions/runs/98', api.calls)
        for field in ['number', 'head', 'base']:
            original = copy.deepcopy(run['pull_requests'][0])
            run['pull_requests'][0][field] = 8 if field == 'number' else {'sha': 'c' * 40}
            self.assertTrue(inspect_pr(FakeAPI(), 7, self.policy))
            run['pull_requests'][0] = original

        # 新审查在发布任何证明之前失败、取消、跳过或排队，不能复用旧绿灯。
        original_id = review['id']
        for conclusion in ['failure', 'cancelled', 'timed_out', 'skipped', None]:
            review['id'] = 100
            review['conclusion'] = conclusion
            api = FakeAPI()
            self.assertTrue(inspect_pr(api, 7, self.policy))
            self.assertEqual(api.statuses[-1], 'failure')
        review.update(id=original_id, conclusion='success')

    def test_review_metadata_binds_queued_runs_and_latest_attempt(self):
        auto = dict(self.run, id=99, path='.github/workflows/codex-code-review.yml', event='workflow_run',
                    head_branch='main', display_title=f'Codex Review pr=0 sha={self.sha}')
        for status, conclusion in [('queued', None), ('completed', 'cancelled'), ('completed', 'failure'), ('completed', 'skipped')]:
            newer = dict(auto, id=100, status=status, conclusion=conclusion)
            self.assertEqual(latest_review(7, self.sha, [auto, newer]), newer)
        manual = dict(auto, id=101, event='workflow_dispatch', display_title='Codex Review pr=7 sha=none')
        self.assertEqual(latest_review(7, self.sha, [auto, manual]), manual)
        self.assertEqual(latest_review(8, self.sha, [auto, manual]), auto)
        self.assertIsNone(latest_review(7, 'c' * 40, [auto]))
        self.assertIsNone(latest_review(7, self.sha, [dict(auto, head_branch='pr-branch')]))
        retry = dict(auto, run_attempt=2, conclusion='failure')
        self.assertEqual(latest_review(7, self.sha, [auto, retry]), retry)


if __name__ == "__main__":
    unittest.main()

