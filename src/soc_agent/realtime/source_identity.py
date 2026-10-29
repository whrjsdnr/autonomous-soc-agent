"""Collector source identity without application/model inference imports."""

from typing import Annotated

from pydantic import StringConstraints

from soc_agent.review.models import Frozen

Text = Annotated[str, StringConstraints(min_length=1, max_length=512)]


class SourceIdentity(Frozen):
    namespace: Text
    generation: Text
    record: Text
