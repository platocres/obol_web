/* Exercise final report exports, including shell-escaped copies of recovered secrets. */
'use strict';
const assert=require('assert'),path=require('path');
const ROOT=path.resolve(__dirname,'../..');
for(const name of ['facts','phases','pack','command','profile','workspace','chain','report'])require(path.join(ROOT,'assets/engine',name+'.js'));
const O=globalThis.OBOL;O.packs={actions:()=>[]};let checks=0;
function check(value,message){assert.ok(value,message);checks++;}
for(const secret of ["O'Brien long SECRET_VARIANT_END",'space $variable "quoted" `tick SECRET_VARIANT_END']) {
 const variants=[O.command.shellQuote(secret),"'"+secret.replace(/'/g,"''")+"'",JSON.stringify(secret),
  '"'+secret.replace(/`/g,'``').replace(/\$/g,'`$').replace(/"/g,'`"')+'"'];
 for(const variant of variants){
  const command='synthetic-client --opaque-argument '+variant;
  const redacted=O.report.redact(command,{secrets:[secret]});
  check(!redacted.includes('SECRET_VARIANT_END'),'Known secret textual variant is fully removed before positional masking');
  check(O.report.redact(command,{secrets:[secret],includeSecrets:true})===command,'Explicit include-secrets option remains effective');
  const facts=new O.facts.FactSet([O.facts.makeFact({kind:'host.up',scope:'host:10.0.0.10'}),O.facts.makeFact({kind:'credential.available',scope:'host:10.0.0.10',value:{user:'fixture-user',password:secret}})]);
  const context=O.report.buildContext({facts,params:{target:'10.0.0.10'},targets:[{ip:'10.0.0.10'}],activities:[{target:'10.0.0.10',at:10,command,stdout:'Synthetic output',produced:['credential.available']}]});
  for(const profile of ['generic','oscp']){
   const doc=O.report.document(profile,context);
   check(!O.report.toMarkdown(doc).includes('SECRET_VARIANT_END'),'Final '+profile+' Markdown does not leak escaped secret suffix');
   check(!O.report.toHtml(doc).includes('SECRET_VARIANT_END'),'Final '+profile+' HTML does not leak escaped secret suffix');
  }
 }
}
console.log('REPORT SECRET VARIANTS: '+checks+' export checks passed');
