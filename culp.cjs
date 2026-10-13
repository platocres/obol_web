const fs=require('fs');const root={};new Function('root','window','globalThis',fs.readFileSync('data/packs-bundle.js','utf8'))(root,root,root);
const pd=root.OBOL.packData;const ids=['smb-share-browse-download','pdf-export-xss-fileread','nvms1000-traversal','heartbleed-memory-leak'];
for(const pk of Object.keys(pd))for(const a of (pd[pk].actions||[])){ if(ids.includes(a.id))
  console.log(a.id+'\n  phase:'+a.phase+'  priority:'+a.priority+'\n  req_all:'+JSON.stringify(a.requires_all)+'\n  req_any:'+JSON.stringify(a.requires_any)+'\n  produces:'+JSON.stringify(a.produces)+'\n'); }
