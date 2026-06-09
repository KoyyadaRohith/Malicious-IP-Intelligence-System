# TODO - 24h Threat Intel Cache + Refresh Feature

- [ ] Step 1: Inspect and confirm remaining code paths (templates + any bulk JS/endpoints)
- [ ] Step 2: Add persistent cache storage (`database/threat_intel_cache.csv`) + CSV DB helpers
- [ ] Step 3: Implement `services/threat_intel_cache.py` (cache-first + refresh, 24h TTL, metadata)
- [ ] Step 4: Add Refresh Intelligence route in `app.py` (force refresh, update cache + history)
- [ ] Step 5: Update scan workflows in `app.py`:
  - [ ] `/investigate` to use cache-first and include cache transparency metadata
  - [ ] `/api/analyze-single` to be cache-first
- [ ] Step 6: Add UI improvements in `templates/ip_investigation.html`:
  - [ ] Refresh button
  - [ ] Display Last Updated, Cache Age, Data Source status
- [ ] Step 7: Harden risk scoring inputs (deterministic defaults, missing-field normalization) in `services/risk_scoring.py`
- [ ] Step 8: Add robust error handling responses for invalid IP and upstream failures
- [ ] Step 9: Compile and run tests (`python -m compileall .`, `python test_pipeline.py`)
- [ ] Step 10: Summarize root cause + implementation changes in final report

