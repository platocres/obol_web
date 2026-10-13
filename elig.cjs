const fs=require('fs');const root={};new Function('root','window','globalThis',fs.readFileSync('data/packs-bundle.js','utf8'))(root,root,root);
const pd=root.OBOL.packData;
for(const pk of Object.keys(pd))for(const a of (pd[pk].actions||[])){
  if(['nvms1000-traversal','pdf-export-xss-fileread','heartbleed-memory-leak'].includes(a.id))
    console.log(a.id,'\n  requires_all:',JSON.stringify(a.requires_all),'\n  requires_any:',JSON.stringify(a.requires_any),'\n  priority:',a.priority,' phase:',a.phase,' transition:',a.transition||'');
}
