/* Migration preserves original evidence while reopening unsupported legacy conclusions. */
'use strict';
const assert = require('assert'), fs = require('fs'), path = require('path'), vm = require('vm');
const ROOT = path.resolve(__dirname, '../..');
const storage = () => { const m = new Map(); return {getItem:k=>m.get(k)||null,setItem:(k,v)=>m.set(k,String(v)),removeItem:k=>m.delete(k)}; };
const sandbox = {console,localStorage:storage(),sessionStorage:storage(),setTimeout(){return 1;},clearTimeout(){},Promise};
sandbox.globalThis=sandbox;sandbox.window=sandbox;vm.createContext(sandbox);
for(const file of ['assets/engine/facts.js','assets/engine/context.js','assets/engine/phases.js','assets/engine/pack.js','assets/ui/store.js']) vm.runInContext(fs.readFileSync(path.join(ROOT,file),'utf8'),sandbox,{filename:file});
const O=sandbox.OBOL,S=O.store,A='10.0.0.10',B='10.0.0.20';let checks=0;
function check(value,message){assert.ok(value,message);checks++;}
function f(kind,value={},source='legacy parser'){return O.facts.makeFact({kind,scope:'host:'+A,value,state:'supported',source});}
function base(){return {name:'Legacy migration',params:{target:A,domain:'alpha.local',username:'alice',password:'Saved secret'},activeTarget:A,
 targets:[{ip:A,domain:'alpha.local'},{ip:B,domain:'beta.local'}],credentials:[{user:'alice',domain:'alpha.local',secret:'Saved secret'}],activities:[],facts:[],checklist:{}};}
async function imported(raw){check(await S.importData(raw.engagement ? raw : {engagement:raw})===1,'Workspace imports through public store API');return S.active();}
(async()=>{
 let raw=base();
 raw.facts=[f('credential.admin',{user:'Administrator',password:'Laps secret',method:'laps'}),
  f('access.admin',{user:'Administrator',nthash:'11223344556677889900aabbccddeeff',method:'sam-dump'}),
  f('credential.validated',{user:'alice',password:'Offline secret',method:'hashcat'}),
  f('foothold.windows',{user:'alice',password:'Saved secret',domain:'alpha.local',service:'winrm',method:'nxc'}),
  f('access.root',{identity:'root',via:'id'},'operator-asserted'),
  f('credential.available',{user:'Administrator',password:'Laps secret',domain:'alpha.local',method:'laps'}),
  f('credential.available',{user:'guessed-user',password:'Gpp secret',method:'gpp-decrypt'})];
 raw.credentials.push({user:'Administrator',domain:'alpha.local',secret:'Laps secret',notes:'Discovered via laps'});
 raw.credentials.push({user:'guessed-user',secret:'Gpp secret',notes:'Discovered via gpp-decrypt'});
 raw.activities=[{target:A,action_id:'old-probe',command:'nxc smb '+A,stdout:'Unrecognized legacy output'}];
 raw.checklist['old-probe']='empty:anon';raw.checklist['manual-move']='done';
 let eng=await imported(raw);
 check(!eng.facts.some(x=>x.kind==='credential.admin'||x.kind==='access.admin'||x.kind==='credential.validated'||x.kind==='foothold.windows'),'Material and login alone no longer grant authentication, privilege, or shell');
 check(eng.facts.some(x=>x.kind==='access.root'&&x.source==='operator-asserted'),'Explicit operator proof is preserved');
 check(eng.activities[0].stdout==='Unrecognized legacy output','Original transcript remains unchanged');
 check(eng.unresolvedLegacyFacts.length===6,'Every downgraded legacy claim keeps its original evidence');
 check(eng.unresolvedLegacyFacts.some(x=>(x.fact.value||{}).password==='Laps secret'),'Original recovered secret remains recoverable in archived evidence');
 check(!O.context.credentials(eng).some(c=>c.password==='Laps secret'||c.password==='Gpp secret'),'Ambiguous legacy material is not silently offered as a resolved credential');
 check(eng.facts.filter(x=>x.kind==='credential.candidate'&&(x.value||{}).association==='unresolved').length===2,'Ambiguous recovered material remains visible as unresolved candidates');
 check(!S.doneIdsForTarget(A)['old-probe'],'Legacy zero-fact retirement is reopened');
 check(S.doneIdsForTarget(A)['manual-move'],'Explicit manual completion remains respected');
 S.setChecklist('fresh-v2-probe','empty:' + O.pack.accessEpoch(S.factSetForTarget(A)),A);
 check(S.doneIdsForTarget(A)['fresh-v2-probe']===true,'v2 empty:<epoch> checklist entries set at runtime are preserved across doneIdsForTarget calls');
 check(eng.unresolvedLegacyChecklist[JSON.stringify([A,'old-probe'])],'Legacy automatic retirement remains inspectable');
 const alice=O.context.credentials(eng).find(c=>c.user==='alice');
 check(S.resolvedContext({target:A}).credentialId===alice.id,'Saved active target retains its unambiguous selection');
 check(!S.resolvedContext({target:B}).credentialId,'Another legacy host does not inherit active credential fields');
 S.selectCredential(null,A);const saved=S.exportEngagement();eng=await imported(saved);
 check(!S.resolvedContext({target:A}).credentialId,'Explicit no-credential selection survives export and import');
 check(eng.unresolvedLegacyFacts.length===6,'Repeated migration does not duplicate or discard archived evidence');
 check(eng.activities[0].stdout==='Unrecognized legacy output','Transcript survives workspace roundtrip');

 raw=base();raw.facts=[f('access.admin',{user:'alice',password:'Saved secret',domain:'alpha.local',service:'smb',method:'nxc'})];
 raw.activities=[{target:A,action_id:'validate-credential',stdout:'SMB '+A+' 445 ALPHA [+] alpha.local\\alice:Saved secret (Pwn3d!)'}];
 eng=await imported(raw);
 check(eng.facts.some(x=>x.kind==='access.admin'&&x.value.authorizationProof==='nxc-pwn3d'),'Explicit historical administrative authorization is retained');
 raw=base();raw.facts=[f('access.admin',{user:'alice',password:'Saved secret',domain:'alpha.local',service:'mssql',method:'nxc'})];
 raw.activities=[{target:A,stdout:'MSSQL '+A+' 1433 ALPHA [+] alpha.local\\alice:Saved secret (Pwn3d!)'}];
 eng=await imported(raw);
 check(!eng.facts.some(x=>x.kind==='access.admin')&&eng.facts.some(x=>x.kind==='db.admin'),'Historical database sysadmin does not become operating-system admin');
 for(const [protocol,realm,password] of [['MSSQL','alpha.local','Saved secret'],['SMB','other.local','Saved secret'],['SMB','alpha.local','Rotated secret']]) {
  raw=base();raw.facts=[f('access.admin',{user:'alice',password:'Saved secret',domain:'alpha.local',service:'smb',method:'nxc'})];
  raw.activities=[{target:A,stdout:protocol+' '+A+' 445 ALPHA [+] '+realm+'\\alice:'+password+' (Pwn3d!)'}];
  eng=await imported(raw);check(!eng.facts.some(x=>x.kind==='access.admin'),'Historical privilege from another protocol, realm, or secret cannot validate an unrelated claim');
 }
 for(const method of ['laps','gpp-decrypt']) {
  raw=base();raw.params={target:A,domain:'alpha.local',username:'Administrator',password:'Ambiguous secret'};
  raw.credentials=[{user:'Administrator',domain:'alpha.local',secret:'Ambiguous secret',notes:'Discovered via '+method}];
  raw.facts=[f('credential.available',{user:'Administrator',password:'Ambiguous secret',domain:'alpha.local',method})];
  eng=await imported(raw);check(!S.resolvedContext().credentialId,'Legacy active fields cannot recreate quarantined material as a configured credential');
  check(eng.contextSelections.unresolvedLegacyParams.password==='Ambiguous secret','Ambiguous legacy input remains recoverable without auto-selection');
  check(!O.context.credentials(eng).some(c=>c.password==='Ambiguous secret'),'Quarantined material is not resurrected during normalization');
 }

 raw=base();raw.facts=[f('credential.available',{user:'Administrator',password:'Bound secret',accountType:'local',targetBinding:A,method:'laps'}),
  f('credential.available',{user:'svc',password:'Bound GPP secret',domain:'alpha.local',method:'gpp-decrypt',association:'single-gpp-source'})];
 raw.credentials=[];raw.params={target:A,domain:'alpha.local'};eng=await imported(raw);
 const local=O.context.credentials(eng).find(c=>c.password==='Bound secret');
 check(local&&local.accountType==='local'&&local.targetBinding===A,'Correctly bound local material remains available after migration');
 check(O.context.credentials(eng).some(c=>c.user==='svc'&&c.password==='Bound GPP secret'),'Explicitly associated GPP material remains available');
 S.selectCredential(local.id,A);check(S.resolvedContext().credential.accountType==='local'&&S.resolvedContext().credential.targetBinding===A,'Selecting local material preserves binding');
 S.setCredentialPin(true);S.setActiveTarget(B);S.setCredentialPin(false);S.setActiveTarget(A);
 check(S.resolvedContext().credentialId===local.id,'Pinning and returning preserve the local record');
 raw=base();raw.credentials=[];raw.params={target:A,domain:'alpha.local'};
 raw.facts=[f('credential.ntlm_hash',{user:'svc-web$',domain:'alpha.local',nthash:'11223344556677889900aabbccddeeff',accountType:'domain',method:'gmsa'})];
 eng=await imported(raw);const gmsa=O.context.credentials(eng).find(c=>c.user==='svc-web$');
 check(gmsa&&gmsa.nthash==='11223344556677889900aabbccddeeff','Recovered gMSA hash is selectable material');
 S.selectCredential(gmsa.id,A);check(S.resolvedContext().facts.has('credential.available')&&!S.resolvedContext().facts.has('credential.validated'),'Selecting gMSA material grants no authentication proof');
 raw=base();raw.facts=[f('access.admin',{user:'Administrator',domain:'alpha.local',password:'Saved secret',service:'wmi',method:'nxc'})];
 eng=await imported(raw);check(!eng.facts.some(x=>x.kind==='access.admin'),'Legacy WMI username inference is also quarantined');
 console.log('CONTEXT MIGRATION: '+checks+' behavioral checks passed');
})().catch(e=>{console.error(e);process.exitCode=1;});
