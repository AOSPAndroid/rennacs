"""Durable checkpoints separate completed work from the safe resume prefix."""


def test_job_stores_effective_configuration_and_safe_resume_cursor(empty_index):
    config = {"version": 2, "shuffle": False, "timeout": 0.75,
              "ports": [22, 80], "rate": 20.0, "concurrency": 2}
    job_id = empty_index.start_job("127.0.0.0/29", "22,80", 6,
                                   seed=0, config=config)
    empty_index.checkpoint_job(job_id, scanned=3, resume_at=1,
                               hosts_up=1, services=2, seed=0)
    job = empty_index.get_job(job_id)
    assert job["scanned"] == 3
    assert job["resume_at"] == 1
    assert job["config"] == config
    assert empty_index.resumable_jobs()[0]["id"] == job_id


def test_resumability_uses_safe_cursor_even_if_completion_counter_is_ahead(empty_index):
    job_id = empty_index.start_job("127.0.0.0/29", "80", 6)
    empty_index.checkpoint_job(job_id, scanned=6, resume_at=1, hosts_up=1, services=1)
    assert [job["id"] for job in empty_index.resumable_jobs()] == [job_id]
