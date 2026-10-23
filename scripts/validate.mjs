import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const catalog=[
 ['application-risk-intelligence','1.0',8,79,78,'7ba85b73c4aac2ff1dbc794fa9c864ad241fc53846b534727290992b5fec5811'],
 ['authentication-threat-intelligence','1.0',9,57,55,'095a4eefda77b9f376e3b1efc87a0a4f49def2b5733afc912f69e04f30d0f325'],
 ['dns-c2-anomaly-intelligence','1.1',10,98,96,'e93aa5de240b094ffbf23877dda476ec8ae56bfaaffcdb98304ce094e4d4c56c'],
 ['global-network-geo-intelligence','2.0',9,74,71,'8add7db9ec4018244289c0106bd91ca024198f1f6d45278972e7942af1aa248e'],
 ['offensive-security-c2-intelligence','1.0',8,75,74,'01f01ff0ba7171b87846185625fb96de76511088abf083ca3e9859633e7d15bc']
];
let failures=0,totalTabs=0,totalPanels=0,totalQueries=0;
const check=(ok,message)=>{if(!ok){failures++;console.error('FAIL: '+message);}};
function walk(v,p,fn){
 if(Array.isArray(v))v.forEach((x,i)=>walk(x,`${p}[${i}]`,fn));
 else if(v&&typeof v==='object')Object.entries(v).forEach(([k,x])=>walk(x,`${p}.${k}`,fn));
 else fn(v,p);
}
for(const [topic,version,tabs,panels,queries,hash] of catalog){
 const slug='sentinelone-'+topic,dir=path.join(root,'dashboards/community',slug+'-latest');
 try{
  const bytes=fs.readFileSync(path.join(dir,slug+'-v'+version+'.json'));
  const obj=JSON.parse(bytes.toString('utf8'));
  check(crypto.createHash('sha256').update(bytes).digest('hex')===hash,slug+': original source bytes changed; review and update baseline intentionally');
  check(obj.configType==='TABBED'&&Array.isArray(obj.tabs),slug+': tabbed export');
  const graphs=obj.tabs.flatMap(t=>{check(typeof t.tabName==='string'&&Array.isArray(t.graphs),slug+': valid tab');return t.graphs||[];});
  check(obj.tabs.length===tabs&&graphs.length===panels,slug+': catalog counts');
  const queryGraphs=graphs.filter(g=>typeof g.query==='string'&&g.query.trim());
  check(queryGraphs.length===queries,slug+': query count');
  for(const g of graphs){
   check(typeof g.title==='string'&&typeof g.graphStyle==='string',slug+': graph title/style');
   check(g.graphStyle==='markdown'?typeof g.markdown==='string':Boolean(g.query?.trim()||g.plots?.length),slug+': graph content');
  }
  const metadata=fs.readFileSync(path.join(dir,'metadata.yaml'),'utf8');
  for(const field of ['data_dependencies','required_fields','description','usecase_type','usecase_action','version','author','validation_status'])check(new RegExp('^  '+field+':\\s+.+$','m').test(metadata),slug+': metadata '+field);
  const notes=fs.readFileSync(path.join(dir,'RESEARCH_NOTES.md'),'utf8');
  check(notes.includes('NeverOff Technology'),slug+': original attribution');
  walk(obj,'$',(value,location)=>{
   if(typeof value!=='string')return;
   for(const [label,re] of [
    ['email',/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i],
    ['IPv4 literal',/\b(?:\d{1,3}\.){3}\d{1,3}\b/],
    ['UUID literal',/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/i],
    ['private key',/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/],
    ['GitHub token',/\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b/],
    ['AWS access key',/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/],
    ['authorization literal',/\bBearer\s+[A-Za-z0-9._~-]{20,}/i]
   ])check(!re.test(value),slug+': '+label+' at '+location);
   check(!/\.(?:apiToken|apiKey|password|secret|tenantId|accountId|siteId)$/i.test(location)||!value.trim(),slug+': sensitive configuration value at '+location);
  });
  totalTabs+=obj.tabs.length;totalPanels+=graphs.length;totalQueries+=queryGraphs.length;
  console.log(`PASS ${slug}: ${tabs} tabs, ${panels} panels, ${queries} queries; source hash preserved`);
 }catch(error){failures++;console.error('FAIL '+slug+': '+error.message);}
}
console.log(`Totals: ${catalog.length} dashboards, ${totalTabs} tabs, ${totalPanels} panels, ${totalQueries} query panels`);
console.log('Scope: static structure and targeted literal scan only; no SentinelOne runtime validation.');
if(failures)process.exitCode=1;
