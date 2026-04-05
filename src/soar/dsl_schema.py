from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, model_validator


class PlaybookStep(BaseModel):  # type: ignore[misc]
    id: str = Field(..., min_length=1, max_length=64)
    action: str = Field(..., min_length=1)
    when: str | None = Field(None, description="Simple Python expression evaluated against context/result.")
    with_args: dict[str, Any] = Field(default_factory=dict)
    continue_on_error: bool = Field(False)

class PlaybookSpec(BaseModel):  # type: ignore[misc]
    id: str = Field(..., min_length=1, max_length=64)
    name: str = Field(..., min_length=1, max_length=128)
    steps: list[PlaybookStep] = Field(..., min_length=1)
    version: str = Field('1')

    @model_validator(mode='after')
    def unique_step_ids(self):  # type: ignore
        steps = getattr(self, 'steps', []) or []
        seen = set()
        for st in steps:
            if st.id in seen:
                raise ValueError(f'duplicate step id: {st.id}')
            seen.add(st.id)
        return self

__all__ = ['PlaybookSpec','PlaybookStep']
