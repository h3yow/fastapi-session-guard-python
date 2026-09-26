"""真实 OS 线程并发下的续期确定性（同步压测 AuthService）。"""

from __future__ import annotations

import concurrent.futures


def test_threadpool_concurrent_refresh_deterministic(app):
    """N 个线程同时用同一张续期凭证：恰 1 个成功，其余全部 session_revoked。

    模拟多线程/多 worker 部署；存储锁保证判定与换发是原子步骤。
    重复多轮排除线程调度偶然性。
    """
    auth = app.state.auth_service

    for round_index in range(20):
        pair = auth.login("alice", "alice-pass-123")

        def use_once(_, token=pair.refresh_token):
            try:
                return auth.refresh(token)
            except Exception as exc:
                return exc

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(use_once, range(8)))

        successes = [o for o in outcomes if not isinstance(o, Exception)]
        failures = [o for o in outcomes if isinstance(o, Exception)]
        assert len(successes) == 1, f"round {round_index}: {outcomes}"
        assert len(failures) == 7
        assert all(f.code == "session_revoked" for f in failures), [f.code for f in failures]
        # 唯一赢家的新访问凭证也因会话被吊销而不可用
        decision = auth.authorize(successes[0].access_token, "view")
        assert decision.code == "session_revoked", decision.code


def test_threadpool_mixed_sessions_stay_independent(app):
    """不同会话在并发续期洪水中互不影响。"""
    auth = app.state.auth_service
    pairs = [auth.login("alice", "alice-pass-123") for _ in range(10)]

    def rotate_one(i):
        try:
            return auth.refresh(pairs[i].refresh_token)
        except Exception as exc:
            return exc

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        outcomes = list(pool.map(rotate_one, range(10)))

    assert all(not isinstance(o, Exception) for o in outcomes), outcomes
    for i, pair in enumerate(outcomes):
        decision = auth.authorize(pair.access_token, "view")
        assert decision.allowed and decision.session_id == pairs[i].session_id
