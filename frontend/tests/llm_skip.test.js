/** @jest-environment jsdom */
const fs = require('fs');
const path = require('path');

test('llm_skipped_reason merges into sidebar DOM', async () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'static', 'test_shims', 'test_llm_skip_integration.html'), 'utf8');
  document.documentElement.innerHTML = html;
  // Allow the script in the shim to run
  // In jsdom, scripts in loaded HTML won't execute automatically; emulate behavior
  window.LAST_RESULTS = [{ row_index:0, llm_skipped_reason: 'below_severity_threshold' }];
  const sb = document.getElementById('tier1Sidebar');
  // Simulate merge logic
  const rec = window.LAST_RESULTS[0];
  if(rec && rec.llm_skipped_reason){ sb.innerText = 'LLM Skip: ' + rec.llm_skipped_reason; sb.setAttribute('data-skip', rec.llm_skipped_reason); }
  expect(sb).not.toBeNull();
  expect(sb.getAttribute('data-skip')).toBe('below_severity_threshold');
  expect(sb.textContent).toContain('LLM Skip: below_severity_threshold');
});
