PR Checklist for feature/fix/test-harness-httpx

- [ ] All unit tests pass locally under `PLATFORM_LITE_INIT=1`.
- [ ] New tests added for deep_analyze (routes, stages, mappings, auto-LLM).
- [ ] Frontend: `csv_analyzer.html` modal added and wired to `/api/v1/assessments/deep_analyze`.
- [ ] Backend: `deep_analyze_endpoints.py` supports `analyze_mode: 'advanced'` and returns `canonical` + `mappings`.
- [ ] No sensitive data is sent to external LLMs by default; Auto-LLM is opt-in.
- [ ] Performance: Advanced mode gated behind UI toggle and server accepts `analyze_mode` flag.
- [ ] Documentation: update developer docs for `analyze_mode`, mapping presets, and UI behavior.
- [ ] Code review: request at least one SME for MITRE/STRIDE mapping accuracy.
- [ ] CI: `.github/workflows/lite-tests.yml` will run tests with `PLATFORM_LITE_INIT=1`.
- [ ] Final step: squash and merge with tidy commit message describing user-visible changes.
