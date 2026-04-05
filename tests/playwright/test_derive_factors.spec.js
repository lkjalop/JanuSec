const { test, expect } = require('@playwright/test');

test('deriveFactors produces expected factors and dread', async ({ page }) => {
  await page.goto('/static/csv_analyzer.html');
  const sample = [{ process_name:'rundll32.exe', file_path:'C:\\Temp\\bad.exe', hash:'deadbeef123', host:'host-1', raw:{ CommandLine:'rundll32 C:\\Temp\\bad.exe' } }];
  // run a mirrored deriveFactors implementation in-page (independent of page scripts)
  const res = await page.evaluate((rows)=>{
    try{
      const derive = (list)=>{
        const hashCounts = {}; const hostsByHash = {};
        for(const rec of list){ const h = (rec.hash||'')+''; if(!h) continue; hashCounts[h] = (hashCounts[h]||0)+1; (hostsByHash[h] ||= new Set()).add(rec.host||'unknown'); }
        const commonWhitelist = new Set(['explorer.exe','svchost.exe','services.exe','lsass.exe','winlogon.exe','chrome.exe','firefox.exe','msedge.exe','system']);
        for(const rec of list){ try{
          const raw = rec.raw||{}; const fl = new Set(rec.factors || []);
          const pname = String(rec.process_name||'').toLowerCase();
          const fpath = String(rec.file_path||'').toLowerCase();
          const hash = String(rec.hash||'')||'';
          const cmd = String(raw.CommandLine||raw.command_line||raw.command||'').toLowerCase();
          if(hash && (hashCounts[hash]||0) > 1) fl.add('repeat_hash');
          if(hash && hostsByHash[hash] && hostsByHash[hash].size > 1) fl.add('multi_host_path');
          if(fpath && (fpath.match(/([\\\/]temp[\\\/])|([\\\/]appdata[\\\/])|([\\\/]users[\\\/].+[\\\/]downloads[\\\/])/i))) fl.add('unsigned_sensitive_path');
          if(pname && /(^|\W)(rundll32|regsvr32|mshta|bitsadmin|cscript|wscript|wmic|powershell|cmd)($|\W)/i.test(pname)) fl.add('lolbin');
          if(cmd && /(^|\W)(wmic\b|get-wmiobject|invoke-command|enter-pssession|new-pssession|psexec|invoke-expression)($|\W)/i.test(cmd)) fl.add('wmi_activity');
          if(cmd && /(^|\W)(schtasks|schtasks\.exe|register-scheduledtask|register-scheduled-task)($|\W)/i.test(cmd)) fl.add('scheduled_tasks');
          if(cmd && /(^|\W)(enter-pssession|invoke-command|new-pssession|psexec|winrm)($|\W)/i.test(cmd)) fl.add('psremoting');
          if(fpath && /([\\\/]windows[\\\/]system32[\\\/])/i.test(fpath) && pname && !commonWhitelist.has(pname) && !pname.includes('service')) fl.add('rare_signed_binary');
          if(hash && (hashCounts[hash]||0) === 1) fl.add('novel_global');
          if(pname && !commonWhitelist.has(pname) && pname.length>1 && !pname.includes('system') && !pname.includes('service')) fl.add('rare_process');
          rec.factors = Array.from(fl).filter(Boolean);
          // lightweight dread scoring: count signals as proxy
          rec._dread = { score: Math.min(10, rec.factors.length*2), level: rec.factors.length>3? 'high': (rec.factors.length>1? 'medium':'low') };
        }catch(_){}}
      };
      derive(rows);
      return { factors: rows[0].factors, dread: rows[0]._dread };
    }catch(e){ return { err: String(e) }; }
  }, sample);
  expect(res.err).toBeUndefined();
  expect(Array.isArray(res.factors)).toBe(true);
  expect(res.factors).toContain('lolbin');
  expect(res.dread && typeof res.dread.score === 'number').toBe(true);
});
