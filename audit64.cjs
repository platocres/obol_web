const fs=require('fs');const root={};new Function('root','window','globalThis',fs.readFileSync('data/packs-bundle.js','utf8'))(root,root,root);
const pd=root.OBOL.packData;
const NEW=new Set(require('child_process').execSync('cat /tmp/claude-0/-home-user/f47a614a-c38d-5356-8ab2-5b865300b35a/scratchpad/fn-inject-block.txt').toString().match(/^  "([^"]+)":/gm).map(s=>s.match(/"([^"]+)"/)[1]).concat(['smb-share-browse-download']));
// "bare" gates = a port/reachable/generic that makes an exploit/loot move eligible at recon
const BARE=/^port:|^http\.reachable$|^smb\.reachable$|^web\.tech$|^web\.server$|^ftp\.reachable$/;
const SECRET=/^credential\.|^loot\.|^objective\.|^hash\.|^access\.|^foothold\./;
const rows=[];
for(const pk of Object.keys(pd))for(const a of (pd[pk].actions||[])){
  if(!NEW.has(a.id))continue;
  const ra=a.requires_any||[], rl=a.requires_all||[];
  const bare=ra.filter(x=>BARE.test(x));
  const specific=ra.filter(x=>!BARE.test(x));
  const producesSecret=(a.produces||[]).some(x=>SECRET.test(x));
  // flag: has a bare gate AND (produces a secret OR phase exploit/loot) AND requires_all doesn't already pin a specific signal
  if(bare.length && producesSecret && rl.length===0){
    rows.push({id:a.id,phase:a.phase,bare:bare,specific:specific,produces:(a.produces||[]).filter(x=>SECRET.test(x))});
  }
}
console.log('moves with bare-gate + secret-produce (candidates to tighten):',rows.length);
for(const r of rows) console.log(`  ${r.id} [${r.phase}]  bare=${JSON.stringify(r.bare)} specific=${JSON.stringify(r.specific)}`);
