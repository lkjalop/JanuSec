const fs=require('fs'); const s=fs.readFileSync('frontend/static/js/csv_analyzer.js','utf8'); let line=1,col=0; let state='normal'; let opener=null; let stack=[]; for(let i=0;i<s.length;i++){ const ch=s[i]; col++; if(ch==='\n'){ line++; col=0; if(state==='linecomment') state='normal'; continue; } if(state==='normal'){ if(ch==='/'){ const nxt=s[i+1]; if(nxt==='/' ){ state='linecomment'; i++; col++; continue;} if(nxt==='*'){ state='blockcomment'; i++; col++; continue;} } if(ch==="'" || ch==='"'){ state='string'; opener=ch; stack.push({type:'string',line,col,opener:ch}); continue; } if(ch==='`'){ state='template'; stack.push({type:'template',line,col}); continue; } if(ch==='(' || ch==='{' || ch==='['){ stack.push({type:'bracket',ch,line,col}); continue;} if(ch===')' || ch==='}' || ch===']'){ // pop matching bracket
  let expected = ch===')'?'(':(ch==='}'?'{':'[');
  // find last bracket
  for(let j=stack.length-1;j>=0;j--){ if(stack[j].type==='bracket'){ if(stack[j].ch===expected){ stack.splice(j,1); break;} else { /* mismatch */ } }} continue; }
 } else if(state==='string'){ if(ch==='\\'){ i++; col++; continue;} if(ch===opener){ state='normal'; stack.pop(); opener=null; continue; } }
 else if(state==='template'){ if(ch==='\\'){ i++; col++; continue;} if(ch==='`'){ state='normal'; stack.pop(); continue;} if(ch==='${'){ /* enter expression - but detecting is complex */ } }
 else if(state==='blockcomment'){ if(ch==='*' && s[i+1]==='/'){ state='normal'; i++; col++; continue; } }
}
console.log('end state', state); console.log('stack tail', stack.slice(-6));
