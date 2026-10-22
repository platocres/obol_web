/* Coverage metadata is a declaration. Only actual supported parser output is an observation. */
'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const ROOT = path.resolve(__dirname, '../..');
const sandbox = { console:{log(){},warn(){}} }; sandbox.globalThis=sandbox; vm.createContext(sandbox);
function load(file){vm.runInContext(fs.readFileSync(path.join(ROOT,file),'utf8'),sandbox,{filename:file});}
load('assets/engine/facts.js'); load('assets/engine/parsers/common.js');
['nmap','directory','creds','host','web','services','database','websource','findings','shape','pivot','dns','blockers','nxc-catalog','index'].forEach(n=>load('assets/engine/parsers/'+n+'.js'));
load('assets/engine/decisionmap.js');
const O=sandbox.OBOL, F=O.facts, DM=O.decisionMap;
const {verifyCorpus}=require('../../tools/verify-parser-corpus.js');
let checks=0;
function check(value,message){assert.ok(value,message);checks++;}
const nmap='Nmap scan report for 10.10.10.10\nHost is up.\nPORT STATE SERVICE\n445/tcp open microsoft-ds\nNmap done: 1 IP address (1 host up) scanned in 0.1 seconds';
const command='nmap -sV 10.10.10.10';
const moves=[
  {id:'shown',produces:['ports.open']},{id:'declared-only',produces:['access.admin']},{id:'no-sample',produces:['access.admin']},
  {id:'some-shown',produces:['ports.open','access.admin']},{id:'refuted-only',produces:['access.admin']},
  {id:'throws',produces:['ports.open']},{id:'diagnostic',produces:['ports.open']},{id:'steps',produces:['ports.open','hash.ntlm']},
  {id:'manual',produces:['listener.started']}
];
O.packs={actions:()=>moves};
O.PARSER_SIGNATURES={declared:{emits:['ports.open','access.admin','hash.ntlm']}};
const actual=O.parsers.parseActionOutput, seen=[];
O.parsers.parseActionOutput=opts=>{
  seen.push({id:opts.actionId,command:opts.command});
  if(opts.actionId==='throws')throw new Error('intentional coverage failure');
  if(opts.actionId==='refuted-only')return {facts:[F.makeFact({kind:'access.admin',state:'refuted',scope:opts.scope,source:opts.command})]};
  const result=actual(opts);
  if(opts.actionId==='diagnostic')result.diagnostics=[{parser:'injected',message:'intentional coverage diagnostic'}];
  return result;
};
let coverage=DM.parserCoverage();
check(coverage.shown.status==='nofixture','Unloaded samples cannot be labeled verified by declared capability');
O.STUDY_FIXTURES={shown:{cmd:command,output:nmap},'declared-only':{cmd:'unrecognized-tool',output:'No matching supported output'},
  'some-shown':{cmd:command,output:nmap},'refuted-only':{cmd:'fixture',output:'Access was not established'},
  throws:{cmd:command,output:nmap},diagnostic:{cmd:command,output:nmap},
  steps:{steps:[{cmd:command,output:nmap},{cmd:'secretsdump 10.10.10.10',output:'alice:1105:aad3b435b51404eeaad3b435b51404ee:11223344556677889900aabbccddeeff:::'}]}};
coverage=DM.parserCoverage();
check(coverage.shown.status==='verified' && coverage.shown.hit.includes('ports.open'),'A loaded real sample verifies an actually observed result');
check(coverage['declared-only'].capabilityStatus==='declared' && coverage['declared-only'].status==='unverified','A declared parser capability cannot substitute for an observed sample result');
check(coverage['no-sample'].status==='nofixture','Missing samples remain explicitly unverified');
check(coverage['some-shown'].status==='partial' && coverage['some-shown'].unverified.includes('access.admin'),'Partial observed coverage names the still unverified result');
check(coverage['refuted-only'].status==='unverified' && !coverage['refuted-only'].minted.includes('access.admin'),'Refuted output cannot verify a supported result');
check(coverage.throws.status==='parser-error' && coverage.throws.diagnostics.length>0,'Thrown parser errors stay visible rather than becoming verification');
check(coverage.diagnostic.status==='parser-error' && coverage.diagnostic.minted.includes('ports.open'),'A partial parser fault retains observations while withholding verification');
check(coverage.steps.status==='verified','Ordered fixture samples can demonstrate different result families');
check(seen.some(s=>s.id==='steps'&&s.command===command)&&seen.some(s=>s.id==='steps'&&/^secretsdump/.test(s.command)),'Each fixture step is actually parsed with its own command');
check(coverage.manual.status==='noproduce','Manual intent is distinguished from parsed output proof');
const wrapped=O.parsers.parseActionOutput; delete O.parsers.parseActionOutput;
check(DM.parserCoverage().shown.status==='noparser','An unavailable parser invalidates cached verification');
O.parsers.parseActionOutput=wrapped;
check(DM.parserCoverage().shown.status==='verified','Parser availability can restore real verification');
O.PARSER_SIGNATURES={declared:{emits:['ports.open','hash.ntlm']}};
check(DM.parserCoverage()['declared-only'].capabilityStatus==='gap' && DM.parserCoverage().shown.status==='verified','Changed signature declarations refresh capability grades without substituting for observed sample results');

const tc={id:'negative-coverage',command,stdout:'unused',expected_supported_kinds:['access.admin']};
let result=verifyCorpus({cases:[tc]},()=>nmap,actual);
check(result.passed===0 && result.failures.length===1,'An expected but absent fact fails corpus verification');
check(!result.minted['access.admin'] && result.minted['ports.open'],'Expected facts are never inserted into observed parser emits');
result=verifyCorpus({cases:[{id:'missing-file',command,stdout:'missing.txt'}]},()=>{throw new Error('missing fixture');},actual);
check(result.passed===0 && /missing fixture/.test(result.failures[0].errors.join(' ')),'Unreadable fixture files produce explicit verification failure');
result=verifyCorpus({cases:[{id:'broken-parser',command}]},()=>nmap,()=>{throw new Error('intentional parser failure');});
check(result.passed===0 && result.total===1,'Parser exceptions never silently inflate passing corpus totals');
result=verifyCorpus({defaults:{forbidden_supported_kinds:['access.admin']},cases:[{id:'forbidden',command}]},()=>'',()=>({facts:[F.makeFact({kind:'access.admin',source:command,scope:'host:10.10.10.10'})]}));
check(result.passed===0 && /Forbidden supported kind/.test(result.failures[0].errors.join(' ')),'Corpus verification rejects unsupported privilege overclaims');
const fixtureDir=path.join(ROOT,'tests/engine/fixtures/parser');
const manifest=JSON.parse(fs.readFileSync(path.join(fixtureDir,'manifest.json'),'utf8'));
result=verifyCorpus(manifest,c=>fs.readFileSync(path.join(fixtureDir,c.stdout),'utf8'),actual);
check(result.passed===result.total && result.total>=81,'The complete actual parser corpus passes its real positive and negative assertions');
console.log('PARSER COVERAGE CONTRACT: '+checks+' checks passed; actual corpus '+result.passed+'/'+result.total);
