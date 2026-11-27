"""合并门禁回归；仅由 GitHub Actions 执行。"""
import copy
import json
from pathlib import Path
import unittest

from pr_merge_gate import evaluate, review_verdict, accepted_ids, step_aliases, inspect_pr, latest_review, event_targets, REVIEW_STEPS, GitHub, run_event


class CollectorAPI:
    """离线模拟多 attempt 和自动审查去重，未知请求直接失败。"""
    repo = 'owner/example'
    graphql = 'https://api.example.com/graphql'

    def __init__(self, case):
        self.sha = case.sha
        self.base = 'b' * 40
        self.run = dict(case.run, pull_requests=[
            {'number': 7, 'head': {'sha': self.sha}, 'base': {'sha': self.base}}])
        self.review = dict(case.run, id=99, path='.github/workflows/codex-code-review.yml',
                           event='workflow_run', head_branch='main',
                           display_title=f'Codex Review pr=0 sha={self.sha}')
        self.reviews = [self.review]
        self.jobs = {(1, 1): [copy.deepcopy(case.job)], (99, 1): [dict(case.job, name='review', steps=[
            dict(case.job['steps'][0], name=n) for n in REVIEW_STEPS])]}
        self.proof = {'head': self.sha, 'base': self.base, 'findings': 0, 'blocking': 0, 'ids': {}, 'run': 99, 'attempt': 1}
        self.comments = [{'id': 1000, 'user': {'login': 'github-actions[bot]', 'type': 'Bot'},
                          'body': f'<!-- codex-review-verdict sha={self.sha} base={self.base} findings=0 blocking=0 run=99 attempt=1 -->'}]
        self.comment_nodes = {}
        self.fresh = {}
        self.statuses = []
        self.calls = []
        self.peers = []
        self.run_reads = 0
        self.new_run = None

    def request(self, path):
        self.calls.append(path)
        if path == 'pulls/7':
            return {'state': 'open', 'head': {'sha': self.sha}, 'base': {'sha': self.base, 'ref': 'main'}}
        runs = {r['id']: r for r in [self.run] + self.reviews}
        rid = int(path.removeprefix('actions/runs/'))
        return copy.deepcopy(self.fresh.get(rid, runs[rid]))

    def pages(self, path, key=None):
        self.calls.append(path)
        if path.startswith('commits/'):
            return self.peers
        if path.startswith('actions/workflows/'):
            return copy.deepcopy(self.reviews)
        if path.startswith('actions/runs?'):
            self.run_reads += 1
            if self.new_run and self.run_reads > 1:
                return [copy.deepcopy(self.run), copy.deepcopy(self.new_run)]
            return [copy.deepcopy(self.run)]
        if path == 'issues/7/comments':
            return copy.deepcopy(self.comments)
        parts = path.split('/')
        assert parts[0:2] == ['actions', 'runs'] and parts[3] == 'attempts' and parts[5] == 'jobs', path
        return copy.deepcopy(self.jobs[(int(parts[2]), int(parts[4]))])

    def attestation(self, run):
        assert run['id'] == self.proof['run']
        return copy.deepcopy(self.proof)

    def unedited_comment_ids(self, comments):
        return GitHub.unedited_comment_ids(self, comments)

    def _request(self, url, data):
        assert url == self.graphql, url
        assert 'lastEditedAt' in data['query'], data
        return {'data': {'nodes': [self.comment_nodes.get(node_id) for node_id in data['variables']['ids']]}}

    def status(self, sha, state, description):
        self.statuses.append(state)

    def deduplicate(self):
        duplicate = dict(self.review, id=100)
        self.reviews.append(duplicate)
        steps = [dict(name=n, status='completed', conclusion='success')
                 for n in ['Checkout review policy', 'Select PR']]
        steps += [dict(name=n, status='completed', conclusion='skipped') for n in REVIEW_STEPS]
        self.jobs[(100, 1)] = [dict(name='review', status='completed', conclusion='success', steps=steps)]
        return duplicate


class GateTests(unittest.TestCase):
    def test_scheduled_scan_retains_heads_and_continues_after_pr_lookup_failure(self):
        from unittest.mock import patch
        import os

        class ScanAPI:
            def __init__(self):
                self.reads, self.statuses = [], []

            def pages(inner, path, key=None):
                return [{'number': n, 'head': {'sha': sha}} for n, sha in [(7, self.sha), (8, 'b' * 40)]]

            def request(self, path):
                self.reads.append(path)
                if path == 'pulls/7':
                    raise OSError('PR unavailable')
                return {'state': 'closed'}

            def status(self, sha, state, description):
                self.statuses.append((sha, state))

        api = ScanAPI()
        with patch.dict(os.environ, {'PR_NUMBER': '', 'DRY_RUN': 'false'}):
            with self.assertRaises(OSError):
                run_event(api, {}, self.policy)
        self.assertEqual(api.reads, ['pulls/7', 'pulls/8'])
        self.assertEqual(api.statuses, [(self.sha, 'failure')])

    def test_event_resolution_and_initial_pr_api_errors_revoke_known_head(self):
        from unittest.mock import patch
        import os

        for stage in ['targets', 'pr']:
            class BrokenAPI:
                def __init__(self):
                    self.statuses = []

                def pages(inner, path, key=None):
                    if stage == 'targets':
                        raise OSError('target lookup failed')
                    return [{'number': 7, 'state': 'open', 'head': {'sha': self.sha}, 'base': {'ref': 'main'}}]

                def request(self, path):
                    raise OSError('PR lookup failed')

                def status(self, sha, state, description):
                    self.statuses.append((sha, state))

            api = BrokenAPI()
            event = {'action': 'in_progress', 'workflow_run': self.run}
            with patch.dict(os.environ, {'PR_NUMBER': '', 'DRY_RUN': 'false'}):
                with self.assertRaises(OSError):
                    run_event(api, event, self.policy)
            self.assertEqual(api.statuses[-1], (self.sha, 'failure'))

    def test_initial_status_read_failure_attempts_failure_publication(self):
        class InitialFailure(CollectorAPI):
            def status(self, sha, state, description):
                if state == 'pending':
                    raise OSError('status lookup failed')
                super().status(sha, state, description)

        api = InitialFailure(self)
        with self.assertRaises(OSError):
            inspect_pr(api, 7, self.policy)
        self.assertEqual(api.statuses, ['failure'])

    def test_failed_dedup_lookup_cannot_prevent_blocking_status(self):
        from unittest.mock import patch
        import os

        class LookupFailure(GitHub):
            def __init__(self):
                self.posts = []

            def pages(self, path, key=None):
                raise OSError('status lookup unavailable')

            def request(self, path, data=None):
                self.posts.append(data)

        api = LookupFailure()
        with patch.dict(os.environ, {'GATE_RUN_URL': 'https://example.com/run'}):
            with self.assertRaises(OSError):
                api.status(self.sha, 'success', 'must not publish')
            api.status(self.sha, 'failure', 'evidence unavailable')
        self.assertEqual([p['state'] for p in api.posts], ['failure', 'failure'])

    def test_new_required_run_created_during_collection_blocks(self):
        api = CollectorAPI(self)
        api.new_run = dict(api.run, id=2, status='queued', conclusion=None)
        self.assertTrue(inspect_pr(api, 7, self.policy))
        self.assertEqual(api.statuses[-1], 'failure')

    def test_shared_sha_cannot_override_another_pr_failure(self):
        class PeerAPI(CollectorAPI):
            def request(self, path):
                return super().request('pulls/7' if path == 'pulls/8' else path)

            def pages(self, path, key=None):
                if path == 'issues/8/comments':
                    return []
                return super().pages(path, key)

        api = PeerAPI(self)
        api.peers = [{'number': 8, 'state': 'open', 'head': {'sha': self.sha}, 'base': {'ref': 'main'}}]
        self.assertTrue(inspect_pr(api, 7, self.policy))
        self.assertEqual(api.statuses[-1], 'failure')

    def test_cargo_executable_uses_current_artifact_not_directory_layout(self):
        from cargo_test_executable import executable
        artifact = {'reason': 'compiler-artifact', 'target': {'name': 'performance_baseline'},
                    'profile': {'test': True}, 'executable': '/tmp/target/debug/build/pkg/out/test'}
        self.assertEqual(executable([json.dumps(artifact)]), artifact['executable'])
        chain = dict(artifact, target={'name': 'chain_systemd_e2e'})
        self.assertEqual(executable(map(json.dumps, [artifact, chain]), 'chain_systemd_e2e'), chain['executable'])
        for messages in [[], [artifact, artifact], [dict(artifact, executable=None)],
                         [dict(artifact, profile={'test': False})]]:
            with self.assertRaises(ValueError):
                executable(map(json.dumps, messages))

    def test_status_publication_is_idempotent_but_revokes_success_on_new_run(self):
        class StatusAPI(GitHub):
            def __init__(self):
                self.history = []

            def pages(self, path, key=None):
                return list(reversed(self.history))

            def request(self, path, data=None):
                self.history.append(data)

        import os
        from unittest.mock import patch
        api = StatusAPI()
        initial = '正在核对当前 head 的必需运行及独立审查'
        with patch.dict(os.environ, {'GATE_RUN_URL': 'https://example.com/run'}):
            api.status('a' * 40, 'pending', initial)
            api.status('a' * 40, 'success', 'verified')
            for _ in range(1100):
                api.status('a' * 40, 'pending', initial)
                api.status('a' * 40, 'success', 'verified')
            self.assertEqual(len(api.history), 2)
            api.status('a' * 40, 'pending', '新的运行已开始')
            api.status('a' * 40, 'pending', '新的运行已开始')
            self.assertEqual(api.history[-1]['state'], 'pending')
            self.assertEqual(len(api.history), 3)
            api.status('a' * 40, 'failure', 'blocked')
            for _ in range(1100):
                api.status('a' * 40, 'pending', initial)
                api.status('a' * 40, 'failure', 'blocked')
            self.assertEqual(len(api.history), 4)

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
        marker = f"<!-- codex-review-verdict sha={self.sha} base={base} findings=0 blocking=0 run=99 attempt=1 -->"
        comment = {"id": 1000, "user": {"login": "github-actions[bot]", "type": "Bot"}, "body": marker}
        run = dict(self.run, id=99, path=".github/workflows/codex-code-review.yml", event="workflow_run", head_branch="main")
        run['attestation'] = {'head': self.sha, 'base': base, 'findings': 0, 'blocking': 0, 'ids': {}, 'run': 99, 'attempt': 1}
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
            jobs[rid] = [dict(self.job, name=name, steps=[dict(self.job['steps'][0], name=step_aliases(s)[0]) for s in steps])
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

    def test_step_alias_requires_exactly_one_successful_listed_name(self):
        old, new = 'Prepare one managed node', 'Prepare two managed nodes'
        policy = {'ci.yml': {'unit': [{'any_of': [old, new]}]}}
        step = self.job['steps'][0]
        def jobs_with(*names, conclusion='success'):
            return {1: [dict(self.job, steps=[dict(step, name=n, conclusion=conclusion) for n in names])]}
        self.assertEqual(evaluate(self.sha, policy, [self.run], jobs_with(old)), [])
        self.assertEqual(evaluate(self.sha, policy, [self.run], jobs_with(new)), [])
        # 两个别名都出现、都不出现、只出现未列出的名称或步骤未成功，均拒绝。
        for names, conclusion in [((old, new), 'success'), ((), 'success'),
                                  (('Prepare three managed nodes',), 'success'),
                                  ((new,), 'skipped'), ((old,), 'failure')]:
            with self.subTest(names=names, conclusion=conclusion):
                self.assertTrue(evaluate(self.sha, policy, [self.run], jobs_with(*names, conclusion=conclusion)))
        for bad in [{'any_of': [old]}, {'any_of': [old, old]}, {'any_of': []}, {'any_of': old},
                    {'any_of': [old, new], 'extra': 1}, {'all_of': [old, new]}, [old, new], None]:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    evaluate(self.sha, {'ci.yml': {'unit': [bad]}}, [self.run], jobs_with(old))

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
        comment = {'id': 1000, 'user': {'login': 'github-actions[bot]', 'type': 'Bot'},
                   'body': f'<!-- codex-review-verdict sha={self.sha} base={base} findings=0 blocking=0 run=99 attempt=1 -->'}
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
                if path.startswith('commits/'):
                    return []
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
                return {'head': outer.sha, 'base': base, 'findings': 0, 'blocking': 0, 'ids': {}, 'run': 99, 'attempt': 1}

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

    def test_ci_rerun_requires_fresh_review_not_skipped_prior_evidence(self):
        api = CollectorAPI(self)
        api.deduplicate()
        self.assertTrue(inspect_pr(api, 7, self.policy))
        self.assertEqual(api.statuses[-1], 'failure')

        api = CollectorAPI(self)
        api.deduplicate()
        for step in api.jobs[(100, 1)][0]['steps']:
            if step['name'] in REVIEW_STEPS:
                step['conclusion'] = 'success'
        api.proof = {'head': api.sha, 'base': api.base, 'findings': 0, 'blocking': 0, 'ids': {}, 'run': 100, 'attempt': 1}
        api.comments.append({'id': 1001, 'user': {'login': 'github-actions[bot]', 'type': 'Bot'},
                             'body': f'<!-- codex-review-verdict sha={api.sha} base={api.base} findings=0 blocking=0 run=100 attempt=1 -->'})
        self.assertEqual(inspect_pr(api, 7, self.policy), [])
        self.assertEqual(api.statuses, ['pending', 'success'])
        self.assertIn('actions/runs/100', api.calls)

    def test_review_rerun_attempt_requires_fresh_proof(self):
        api = CollectorAPI(self)
        api.review['run_attempt'] = 2
        api.jobs[(99, 2)] = copy.deepcopy(api.jobs[(99, 1)])
        self.assertTrue(inspect_pr(api, 7, self.policy))
        self.assertEqual(api.statuses[-1], 'failure')
        api.proof['attempt'] = 2
        api.comments.append({'id': 1001, 'user': {'login': 'github-actions[bot]', 'type': 'Bot'},
                             'body': f'<!-- codex-review-verdict sha={api.sha} base={api.base} findings=0 blocking=0 run=99 attempt=2 -->'})
        api.statuses.clear()
        self.assertEqual(inspect_pr(api, 7, self.policy), [])
        self.assertEqual(api.statuses, ['pending', 'success'])

    def test_deduplication_never_bypasses_failed_manual_or_incomplete_review(self):
        for scenario in ['failed', 'cancelled', 'job-skipped', 'manual', 'select-skipped',
                         'review-executed', 'missing-step', 'missing-proof', 'wrong-base', 'findings']:
            with self.subTest(scenario=scenario):
                api = CollectorAPI(self)
                duplicate = api.deduplicate()
                job = api.jobs[(100, 1)][0]
                if scenario in ('failed', 'cancelled'):
                    duplicate['conclusion'] = 'failure' if scenario == 'failed' else 'cancelled'
                elif scenario == 'job-skipped':
                    job['conclusion'] = 'skipped'
                elif scenario == 'manual':
                    duplicate.update(event='workflow_dispatch', display_title='Codex Review pr=7 sha=none')
                elif scenario == 'select-skipped':
                    job['steps'][1]['conclusion'] = 'skipped'
                elif scenario == 'review-executed':
                    job['steps'][3]['conclusion'] = 'success'
                elif scenario == 'missing-step':
                    job['steps'].pop()
                elif scenario == 'missing-proof':
                    api.proof = None
                elif scenario == 'wrong-base':
                    api.base = 'c' * 40
                elif scenario == 'findings':
                    api.comments[0]['body'] = api.comments[0]['body'].replace('findings=0', 'findings=1')
                self.assertTrue(inspect_pr(api, 7, self.policy))
                self.assertEqual(api.statuses[-1], 'failure')

    def test_deduplicated_run_cannot_hide_intervening_review_failure(self):
        api = CollectorAPI(self)
        api.deduplicate()
        api.reviews.append(dict(api.review, id=101, conclusion='failure'))
        api.reviews.append(dict(api.reviews[1], id=102))
        api.jobs[(102, 1)] = copy.deepcopy(api.jobs[(100, 1)])
        self.assertTrue(inspect_pr(api, 7, self.policy))

    def test_failed_jobs_rerun_preserves_successful_jobs_from_earlier_attempts(self):
        api = CollectorAPI(self)
        api.run['run_attempt'] = 3
        api.jobs[(1, 1)].append(dict(self.job, name='other', conclusion='failure'))
        api.jobs[(1, 2)] = [dict(self.job, name='other', conclusion='failure')]
        api.jobs[(1, 3)] = [dict(self.job, name='other')]
        policy = {'ci.yml': {'unit': ['Test'], 'other': ['Test']}}
        self.assertEqual(inspect_pr(api, 7, policy), [])
        self.assertEqual(api.statuses[-1], 'success')
        for attempt in [1, 2, 3]:
            self.assertIn(f'actions/runs/1/attempts/{attempt}/jobs', api.calls)

    def test_latest_job_execution_still_must_succeed_and_be_unique(self):
        for scenario in ['failed', 'skipped', 'duplicate', 'step-skipped']:
            with self.subTest(scenario=scenario):
                api = CollectorAPI(self)
                api.run['run_attempt'] = 2
                api.jobs[(1, 2)] = [copy.deepcopy(self.job)]
                job = api.jobs[(1, 2)][0]
                if scenario == 'duplicate':
                    api.jobs[(1, 2)].append(copy.deepcopy(job))
                elif scenario == 'step-skipped':
                    job['steps'][0]['conclusion'] = 'skipped'
                else:
                    job['conclusion'] = 'failure' if scenario == 'failed' else 'skipped'
                self.assertTrue(inspect_pr(api, 7, self.policy))

    def test_rerun_during_evidence_collection_still_blocks(self):
        for rid in [1, 99, 100]:
            with self.subTest(rid=rid):
                api = CollectorAPI(self)
                duplicate = api.deduplicate()
                run = {1: api.run, 99: api.review, 100: duplicate}[rid]
                api.fresh[rid] = dict(run, run_attempt=2)
                self.assertTrue(inspect_pr(api, 7, self.policy))
                self.assertEqual(api.statuses[-1], 'failure')

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
        push_review = dict(auto, id=102, conclusion='skipped', display_title='Codex Review pr=0 sha=none')
        self.assertEqual(latest_review(7, self.sha, [auto, push_review]), auto)
        self.assertEqual(event_targets(None, {'workflow_run': push_review}), ([], None))
        workflow = Path(__file__).resolve().parents[2] / '.github/workflows/codex-code-review.yml'
        self.assertIn("sha=${{ github.event.workflow_run.event == 'pull_request' && github.event.workflow_run.head_sha || 'none' }}", workflow.read_text())
        self.assertNotIn("该提交已有成功的 Codex 审查，跳过。", workflow.read_text())

    def test_workflow_events_only_select_current_associated_pr(self):
        outer = self

        class FakeAPI:
            def pages(self, path):
                self.path = path
                return [dict(number=number, state='open', head={'sha': sha}, base={'ref': base})
                        for number, sha, base in [(7, outer.sha, 'main'), (8, 'c' * 40, 'main'), (9, outer.sha, 'other')]]

        api = FakeAPI()
        self.assertEqual(event_targets(api, {'workflow_run': dict(self.run, event='push')}), ([], None))
        self.assertFalse(hasattr(api, 'path'))
        self.assertEqual(event_targets(api, {'workflow_run': self.run}), ([7], self.sha))
        self.assertEqual(api.path, f'commits/{self.sha}/pulls')
        auto = dict(self.run, path='.github/workflows/codex-code-review.yml', event='workflow_run',
                    head_branch='main', display_title=f'Codex Review pr=0 sha={self.sha}')
        self.assertEqual(event_targets(api, {'workflow_run': auto}), ([7], self.sha))
        manual = dict(auto, event='workflow_dispatch', display_title='Codex Review pr=7 sha=none')
        self.assertEqual(event_targets(api, {'workflow_run': manual}), ([7], None))
        self.assertEqual(event_targets(api, {'workflow_run': dict(manual, head_branch='untrusted')}), ([], None))
        self.assertEqual(event_targets(api, {}), (None, None))



class BlockingAndAcceptTests(unittest.TestCase):
    """门禁只认所有者在当前审查评论之后发出的、明确绑定该评论的原始命令。"""
    SHA, BASE, OWNER = 'a' * 40, 'b' * 40, 'owner'

    def review(self, ids, sha=None, comment_id=1000, run=99, blocking=None, findings=None):
        sha = sha or self.SHA
        blocking = sum(1 for v in ids.values() if v <= 1) if blocking is None else blocking
        findings = len(ids) if findings is None else findings
        marker = (f'<!-- codex-review-verdict sha={sha} base={self.BASE} findings={findings} '
                  f'blocking={blocking} run={run} attempt=1 -->')
        comment = {'id': comment_id, 'user': {'login': 'github-actions[bot]', 'type': 'Bot'}, 'body': marker}
        run_data = {'id': run, 'run_attempt': 1, 'path': '.github/workflows/codex-code-review.yml',
                    'event': 'workflow_run', 'head_branch': 'main', 'status': 'completed', 'conclusion': 'success',
                    'attestation': {'head': sha, 'base': self.BASE, 'findings': len(ids),
                                    'blocking': sum(1 for v in ids.values() if v <= 1),
                                    'ids': dict(ids), 'run': run, 'attempt': 1}}
        job = {'name': 'review', 'status': 'completed', 'conclusion': 'success',
               'steps': [{'name': n, 'status': 'completed', 'conclusion': 'success'} for n in REVIEW_STEPS]}
        return comment, {run: run_data}, {run: [job]}

    def accept(self, body, comment_id=1100, login=None, association='OWNER', kind='User'):
        return {'id': comment_id, 'user': {'login': login or self.OWNER, 'type': kind},
                'author_association': association, 'body': body}

    @staticmethod
    def unedited(candidates):
        return {candidate['id'] for candidate in candidates}

    def verdict(self, comments, runs, jobs, sha=None):
        return review_verdict(sha or self.SHA, self.BASE, comments, runs, jobs, owner=self.OWNER,
                              unedited_comment_ids=self.unedited)

    def test_only_suggestions_give_blocking_zero_and_pass(self):
        comment, runs, jobs = self.review({'F1': 2, 'F2': 3})
        self.assertIn('findings=2 blocking=0', comment['body'])
        self.assertEqual(self.verdict([comment], runs, jobs), [])

    def test_p1_blocks_and_owner_accept_after_review_passes(self):
        comment, runs, jobs = self.review({'F1': 1, 'F2': 2})
        errors = self.verdict([comment], runs, jobs)
        self.assertTrue(errors)
        self.assertIn('F1', errors[-1])
        reason = '这一条已经人工确认是误报-SECRET-REASON'
        waiver = self.accept(f'/accept F1 review=1000 {reason}')
        self.assertEqual(self.verdict([comment, waiver], runs, jobs), [])
        # P0 同样阻塞，同样可以豁免；理由文本不出现在门禁输出里。
        comment, runs, jobs = self.review({'F1': 0, 'F2': 1})
        errors = self.verdict([comment, waiver], runs, jobs)
        self.assertTrue(errors)
        self.assertIn('F2', errors[-1])
        self.assertNotIn(reason, ''.join(errors))
        self.assertEqual(self.verdict([comment, self.accept('/accept F1 review=1000 a'),
                                       self.accept('/accept F2 review=1000 b', 1101)],
                                      runs, jobs), [])

    def test_accept_requires_owner_reason_exact_id_and_later_comment(self):
        comment, runs, jobs = self.review({'F1': 1, 'F2': 2})
        invalid = [
            self.accept('/accept F1 review=1000 理由', login='someone-else', association='COLLABORATOR'),
            self.accept('/accept F1 review=1000 理由', association='COLLABORATOR'),
            self.accept('/accept F1 review=1000 理由', login='owner', kind='Bot'),
            self.accept('/accept F1 review=1000 理由', login='github-actions[bot]', kind='Bot', association='NONE'),
            self.accept('/accept F1 review=1000'),
            self.accept('/accept F1 review=1000   '),
            self.accept('/accept F1 review=1000\n理由写在第二行'),
            self.accept('/accept F2 review=1000 只豁免了建议项'),
            self.accept('/accept F01 review=1000 编号不合法'),
            self.accept('/accept f1 review=1000 小写'),
            self.accept('/accept F1,F2 review=1000 多个'),
            self.accept('请处理 /accept F1 review=1000 不在行首'),
            self.accept('/accept F1 review=9999 指向其他审查'),
            self.accept('/accept F1 没有绑定审查'),
            self.accept('/accept F1 review=1000 理由', comment_id=999),  # 早于审查评论
            dict(self.accept('/accept F1 review=1000 理由'), id='1100'),
        ]
        for bad in invalid:
            with self.subTest(bad=bad):
                self.assertTrue(self.verdict([comment, bad], runs, jobs))
        self.assertEqual(accepted_ids([self.accept('/accept F1 review=1000 理由')], '', 1000, {'F1'}, self.unedited),
                         set())
        self.assertEqual(accepted_ids([self.accept('/accept F12 review=1000 理由\r\n补充说明')], self.OWNER,
                                      1000, {'F12'}, self.unedited), {'F12'})

    def test_new_commit_invalidates_old_accept(self):
        old_comment, _, _ = self.review({'F1': 1}, sha='c' * 40, comment_id=1000)
        old_accept = self.accept('/accept F1 review=1000 针对旧提交的豁免', comment_id=1100)
        new_comment, runs, jobs = self.review({'F1': 1}, comment_id=1200, run=100)
        # 新 head 的审查评论在旧豁免之后，旧豁免不再生效。
        self.assertTrue(self.verdict([old_comment, old_accept, new_comment], runs, jobs))
        self.assertEqual(self.verdict([old_comment, old_accept, new_comment,
                                       self.accept('/accept F1 review=1200 重新确认', comment_id=1300)], runs, jobs), [])
        # 同一 head 重新审查（新 run）后，之前的豁免同样失效。
        rerun, rerun_runs, rerun_jobs = self.review({'F1': 1}, comment_id=1400, run=101)
        self.assertTrue(self.verdict([new_comment, self.accept('/accept F1 review=1200 旧', comment_id=1300), rerun],
                                     rerun_runs, rerun_jobs))

    def test_accept_sent_after_rerun_cannot_waive_the_new_f1(self):
        old_comment, _, _ = self.review({'F1': 1}, comment_id=1000, run=99)
        rerun, runs, jobs = self.review({'F1': 1}, comment_id=1100, run=100)
        stale = self.accept('/accept F1 review=1000 针对上一轮 F1', comment_id=1200)
        comments = [old_comment, rerun, stale]
        self.assertIn('F1', ' '.join(self.verdict(comments, runs, jobs)))
        current = self.accept('/accept F1 review=1100 明确豁免新 F1', comment_id=1201)
        self.assertEqual(self.verdict(comments + [current], runs, jobs), [])

    def test_accept_cannot_start_with_markdown_indent_or_a_blank_line(self):
        comment, runs, jobs = self.review({'F1': 1})
        for prefix in (' ', '    ', '\t', '\n', '\r\n'):
            with self.subTest(prefix=prefix):
                errors = self.verdict([comment, self.accept(f'{prefix}/accept F1 review=1000 示例')], runs, jobs)
                self.assertIn('F1', ' '.join(errors))

    def test_blocking_must_match_attestation(self):
        comment, runs, jobs = self.review({'F1': 1, 'F2': 3})
        cases = [
            ('marker blocking', dict(comment, body=comment['body'].replace('blocking=1', 'blocking=0'))),
            ('marker findings', dict(comment, body=comment['body'].replace('findings=2', 'findings=1'))),
            ('old marker', dict(comment, body=comment['body'].replace(' blocking=1', ''))),
        ]
        for name, bad in cases:
            with self.subTest(name=name):
                self.assertTrue(self.verdict([bad], runs, jobs))
        attestation = runs[99]['attestation']
        comments = [comment, self.accept('/accept F1 review=1000 理由')]
        for name, change in [('priority lowered', {'ids': {'F1': 2, 'F2': 3}}),
                             ('blocking lowered', {'blocking': 0}),
                             ('id gap', {'ids': {'F1': 1, 'F3': 3}}),
                             ('bool priority', {'ids': {'F1': True, 'F2': 3}}),
                             ('missing ids', {'ids': None}),
                             ('extra key', {'accepted': ['F1']})]:
            with self.subTest(name=name):
                runs[99]['attestation'] = dict(attestation, **change)
                self.assertTrue(self.verdict(comments, runs, jobs))
        runs[99]['attestation'] = attestation
        self.assertEqual(self.verdict(comments, runs, jobs), [])
        # 运行来源、run/attempt、head/base 的校验保持不变。
        for key, value in [('head_branch', 'feature'), ('path', '.github/workflows/other.yml'),
                           ('run_attempt', 2), ('conclusion', 'failure')]:
            with self.subTest(key=key):
                bad_runs = {99: dict(runs[99], **{key: value})}
                self.assertTrue(self.verdict(comments, bad_runs, jobs))
        for key, value in [('head', 'c' * 40), ('base', 'c' * 40), ('run', 98), ('attempt', 2)]:
            with self.subTest(attestation=key):
                bad_runs = {99: dict(runs[99], attestation=dict(attestation, **{key: value}))}
                self.assertTrue(self.verdict(comments, bad_runs, jobs))

    def test_collector_blocks_p1_until_owner_accept(self):
        case = GateTests('test_success')
        case.setUp()
        api = CollectorAPI(case)
        api.proof.update(findings=2, blocking=1, ids={'F1': 1, 'F2': 2})
        api.comments[0]['body'] = api.comments[0]['body'].replace('findings=0 blocking=0', 'findings=2 blocking=1')
        errors = inspect_pr(api, 7, case.policy)
        self.assertTrue(any('F1' in e for e in errors), errors)
        self.assertEqual(api.statuses[-1], 'failure')
        node_id = 'issue-comment-1001'
        accepted = self.accept('/accept F1 review=1000 已确认可接受', comment_id=1001)
        timestamp = '2026-11-14T00:00:00Z'
        api.comments.append(dict(accepted, node_id=node_id, created_at=timestamp, updated_at=timestamp))
        node = {'id': node_id, 'body': accepted['body'], 'lastEditedAt': None}
        for name, unverifiable in (
            ('same-second edit', dict(node, lastEditedAt=timestamp)),
            ('body changed between reads', dict(node, body='未发布豁免')),
            ('missing edit metadata', {'id': node_id, 'body': accepted['body']}),
            ('missing node', None),
        ):
            with self.subTest(name=name):
                api.comment_nodes[node_id] = unverifiable
                errors = inspect_pr(api, 7, case.policy)
                self.assertTrue(any('F1' in error for error in errors), errors)
                self.assertEqual(api.statuses[-1], 'failure')
        api.comment_nodes[node_id] = node
        api.statuses.clear()
        self.assertEqual(inspect_pr(api, 7, case.policy), [])
        self.assertEqual(api.statuses, ['pending', 'success'])


if __name__ == "__main__":
    unittest.main()
