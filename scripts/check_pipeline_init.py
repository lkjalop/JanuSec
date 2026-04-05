from pathlib import Path
import sys

_repo = Path('.').resolve()
if str(_repo) not in sys.path:
    sys.path.insert(0, str(_repo))

from src.core.event_pipeline.pipeline import EventPipeline


class C: pass


async def main():
    p = EventPipeline(C())
    await p.initialize()
    print('enabled groups:', p._enabled_stage_groups)
    print('active stages count:', len(p._active_stage_definitions))
    print('sample active stages:', [s.name for s in p._active_stage_definitions][:12])


if __name__ == '__main__':
    import asyncio
    asyncio.run(main())
