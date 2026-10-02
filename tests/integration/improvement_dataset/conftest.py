from uuid import uuid4

import pytest_asyncio

from soc_agent.improvement_dataset import (
    ImprovementDatasetBuilder,
    ImprovementDatasetStore,
    migrate_datasets,
)
from tests.integration.feedback.conftest import feedback_case, issue, runtime_case

__all__ = ["feedback_case", "runtime_case"]


@pytest_asyncio.fixture
async def dataset_case(feedback_case):
    c = feedback_case
    migrate_datasets(c.store.database)
    c.datasets = ImprovementDatasetStore(c.feedback_store)
    c.builder = ImprovementDatasetBuilder(c.datasets)
    return c


def submit(c, verdict=None, labels=(), subject="alice", note=""):
    request = c.request.model_copy(
        update={
            "submission_id": uuid4(),
            "verdict": verdict or c.request.verdict,
            "labels": tuple(sorted(labels)),
            "note": note,
        }
    )
    return c.feedback.submit(request, credential=issue(c, request, subject=subject))


def build(c):
    return c.builder.build((c.evaluation.evaluation_id,))
