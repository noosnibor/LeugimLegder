const encoder = new TextEncoder();
const json = (data, status=200, extra={}) => new Response(JSON.stringify(data), {status, headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff',...extra}});
const id=()=>crypto.randomUUID();
const bytes=n=>{const a=new Uint8Array(n);crypto.getRandomValues(a);return a};
const hex=a=>Array.from(new Uint8Array(a),n=>n.toString(16).padStart(2,'0')).join('');
const unhex=s=>Uint8Array.from(s.match(/../g)||[],b=>parseInt(b,16));
const hash=async s=>hex(await crypto.subtle.digest('SHA-256',encoder.encode(s)));
async function pbkdf(password,salt,iterations=100000){const key=await crypto.subtle.importKey('raw',encoder.encode(password),'PBKDF2',false,['deriveBits']);return hex(await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:unhex(salt),iterations},key,256))}
const cookie=(token,age)=>`hl_session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${age}`;
const now=()=>Math.floor(Date.now()/1000);
async function auth(req,env){const token=req.headers.get('Cookie')?.match(/(?:^|;\s*)hl_session=([a-f0-9]{64})(?:;|$)/)?.[1];if(!token)return null;return await env.DB.prepare('SELECT u.id,u.email,u.display_name,u.role,u.person_id FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?').bind(await hash(token),now()).first()}
const guard=(req)=>{const origin=req.headers.get('Origin');return origin===new URL(req.url).origin};
async function body(req){const size=Number(req.headers.get('Content-Length')||0);if(size>900000)return null;const raw=await req.text();if(raw.length>900000)return null;try{return JSON.parse(raw)}catch{return null}}
function validState(s){return s&&typeof s==='object'&&Array.isArray(s.people)&&Array.isArray(s.accounts)&&Array.isArray(s.cycles)&&Array.isArray(s.items)&&s.people.length<100&&s.accounts.length<300&&s.cycles.length<1000&&s.items.length<5000}

// Household-scoped projection: never send another member's financial records to a member.
function memberView(s,pid){
 const out=structuredClone(s);
 delete out.itemTemplates;
 out.people=out.people.filter(p=>p.id===pid);
 out.accounts=out.accounts.filter(a=>a.personId===pid);
 out.items=out.items.map(i=>({...i,budgets:{[pid]:i.budgets?.[pid]||0}}));
 out.cycles=out.cycles.map(c=>({...c,
  opening:Object.fromEntries(Object.entries(c.opening||{}).filter(([key])=>out.accounts.some(a=>a.id===key))),
  incomeEstimates:(c.incomeEstimates||[]).filter(i=>i.personId===pid),
  reportTotals:{income:(c.transactions||[]).filter(t=>t.personId===pid&&t.type==='income').reduce((n,t)=>n+Number(t.amount||0),0),expenses:(c.transactions||[]).filter(t=>t.personId===pid&&t.type==='expense').reduce((n,t)=>n+Number(t.amount||0),0)},
  itemBudgets:Object.fromEntries(Object.entries(c.itemBudgets||{}).map(([key,vals])=>[key,{[pid]:vals?.[pid]||0}])),
  paymentGroups:(c.paymentGroups||[]).filter(g=>g.personId===pid).map(g=>({...g,totalAmount:g.lines.reduce((n,l)=>n+Number(l.amount||0),0),paidAmount:(c.transactions||[]).filter(t=>t.batchId===g.id).reduce((n,t)=>n+Number(t.amount||0),0),adjustments:(g.adjustments||[]).map(x=>({id:x.id,date:x.date,amount:x.amount,note:x.note})),lines:g.lines.filter(l=>!s.items.find(i=>i.id===l.itemId)?.hidden)})),
  transactions:(c.transactions||[]).filter(t=>t.personId===pid&&out.accounts.some(a=>a.id===t.accountId)&&!s.items.find(i=>i.id===t.itemId)?.hidden)
 }));
 return out;
}
function sameJSON(a,b){return JSON.stringify(a)===JSON.stringify(b)}
function safeMemberMerge(full,incoming,pid){
 const allowedAccounts=full.accounts.filter(a=>a.personId===pid);
 if(!full.people.some(p=>p.id===pid)||!sameJSON(incoming.people,[full.people.find(p=>p.id===pid)])||
    !sameJSON(incoming.accounts,allowedAccounts)||
    !sameJSON(incoming.items,memberView(full,pid).items)||
    !sameJSON(incoming.cycles.map(c=>({id:c.id,name:c.name,month:c.month,start:c.start,end:c.end})),
      full.cycles.map(c=>({id:c.id,name:c.name,month:c.month,start:c.start,end:c.end}))))return null;
 if(incoming.currentCycleId!==full.currentCycleId)return null;
 const out=structuredClone(full);
 for(const c of out.cycles){
  const inc=incoming.cycles.find(x=>x.id===c.id);if(!inc)return null;
  if(c.closed&& !sameJSON(inc,memberView(full,pid).cycles.find(x=>x.id===c.id)))return null;
  const owned=allowedAccounts.map(a=>a.id);
  if(!sameJSON(inc.paymentGroups||[],memberView(full,pid).cycles.find(x=>x.id===c.id).paymentGroups))return null;
  if(Object.keys(inc.opening||{}).some(x=>!owned.includes(x))||
    !sameJSON(Object.fromEntries(owned.map(x=>[x,c.opening?.[x]||0])),Object.fromEntries(owned.map(x=>[x,inc.opening?.[x]||0]))))return null;
  const other= c.transactions.filter(t=>t.personId!==pid||!owned.includes(t.accountId)||full.items.find(i=>i.id===t.itemId)?.hidden);
  const mine=inc.transactions||[];
  if(mine.some(t=>full.items.find(i=>i.id===t.itemId)?.hidden||t.personId!==pid||!owned.includes(t.accountId)||!['income','expense'].includes(t.type)||!Number.isFinite(Number(t.amount))||Number(t.amount)<0))return null;
  if(mine.some(t=>t.batchId&&!((c.paymentGroups||[]).some(g=>g.id===t.batchId&&g.personId===pid&&g.lines.some(line=>line.itemId===t.itemId)))))return null;
  for(const group of (c.paymentGroups||[]).filter(g=>g.personId===pid)){
   const batch=mine.filter(t=>t.batchId===group.id);
   const previous=c.transactions.filter(t=>t.batchId===group.id&&!full.items.find(i=>i.id===t.itemId)?.hidden);
   if(previous.length&&!sameJSON(batch,previous))return null;
   if(batch.length&&!previous.length)return null;
   if(batch.length&&!sameJSON(batch,previous))return null;
  }
  if(mine.some(t=>t.sourceType&&!['cash','debit','ach','credit'].includes(t.sourceType)||t.sourceNickname!=null&&(typeof t.sourceNickname!=='string'||t.sourceNickname.length>80)))return null;
  const ids=mine.map(t=>t.id);if(new Set(ids).size!==ids.length||ids.some(id=>other.some(t=>t.id===id)))return null;
  const originalMine=c.transactions.filter(t=>t.personId===pid&&owned.includes(t.accountId)&&!full.items.find(i=>i.id===t.itemId)?.hidden);
  const existingIds=new Set(c.transactions.map(t=>t.id));
  if(mine.some(t=>existingIds.has(t.id)&&!originalMine.some(o=>o.id===t.id)))return null;
  const otherEst=c.incomeEstimates.filter(e=>e.personId!==pid);
  const mineEst=inc.incomeEstimates||[];
  if(mineEst.some(e=>e.personId!==pid||!Number.isFinite(Number(e.amount))||Number(e.amount)<0)||new Set(mineEst.map(e=>e.id)).size!==mineEst.length||mineEst.some(e=>otherEst.some(o=>o.id===e.id)))return null;
  if(mine.some(t=>t.type==='income'&&t.incomeEstimateId&&!mineEst.some(e=>e.id===t.incomeEstimateId)))return null;
  if(Object.keys(inc.itemBudgets||{}).some(id=>!out.items.some(i=>i.id===id)))return null;
  for(const item of out.items){
   const b=inc.itemBudgets?.[item.id]||{};
   if(Object.keys(b).some(key=>key!==pid)||!Number.isFinite(Number(b[pid]||0))||Number(b[pid]||0)<0)return null;
   c.itemBudgets[item.id]={...(c.itemBudgets[item.id]||{}),[pid]:Number(b[pid]||0)};
  }
  c.transactions=[...other,...mine];
  c.incomeEstimates=[...otherEst,...mineEst];
 }
 return out;
}

async function createSession(user,env){const token=hex(bytes(32));await env.DB.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').bind(await hash(token),user.id,now()+60*60*24*14).run();return cookie(token,60*60*24*14)}
async function handle(req,env){const url=new URL(req.url),p=url.pathname,method=req.method;
 if(!p.startsWith('/api/'))return env.ASSETS.fetch(req);
 if(method!=='GET'&&!guard(req))return json({error:'Invalid request origin'},403);
 try{
  if(p==='/api/setup/status'&&method==='GET'){const row=await env.DB.prepare('SELECT COUNT(*) n FROM users').first();return json({setupRequired:!row.n})}
  if(p==='/api/setup'&&method==='POST'){
   if(!env.BOOTSTRAP_TOKEN||env.BOOTSTRAP_TOKEN.length<24)return json({error:'Set a strong BOOTSTRAP_TOKEN using wrangler secret put before setup'},503);
   const b=await body(req);if(!b||b.bootstrapToken!==env.BOOTSTRAP_TOKEN)return json({error:'Invalid setup token'},403);
   if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(b.email||'')||String(b.password||'').length<12||String(b.password||'').length>256||!String(b.name||'').trim())return json({error:'Enter name, valid email and password of at least 12 characters'},400);
   const salt=hex(bytes(16)),pwd=await pbkdf(b.password,salt),userId=id();
   const insert=await env.DB.prepare("INSERT INTO users(id,email,display_name,role,salt,password_hash,iterations) SELECT ?,?,?,'admin',?,?,100000 WHERE NOT EXISTS (SELECT 1 FROM users)").bind(userId,b.email.toLowerCase().trim(),b.name.trim().slice(0,100),salt,pwd).run();
   if(!insert.meta.changes)return json({error:'Household already initialized'},409);
   return json({ok:true},201,{'Set-Cookie':await createSession({id:userId},env)});
  }
  if(p==='/api/login'&&method==='POST'){
   const b=await body(req);const email=String(b?.email||'').toLowerCase().trim();if(email.length>254||!b?.password)return json({error:'Invalid credentials'},401);
   const u=await env.DB.prepare('SELECT * FROM users WHERE email=?').bind(email).first();
   if(!u||await pbkdf(String(b.password),u.salt,u.iterations)!==u.password_hash)return json({error:'Invalid credentials'},401);
   return json({user:{id:u.id,email:u.email,name:u.display_name,role:u.role,personId:u.person_id||null}},200,{'Set-Cookie':await createSession(u,env)});
  }
  const u=await auth(req,env);if(!u)return json({error:'Not authenticated'},401);
  if(p==='/api/me'&&method==='GET')return json({user:{id:u.id,email:u.email,name:u.display_name,role:u.role,personId:u.person_id||null}});
  if(p==='/api/logout'&&method==='POST'){const token=req.headers.get('Cookie')?.match(/hl_session=([a-f0-9]{64})/)?.[1];if(token)await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await hash(token)).run();return json({ok:true},200,{'Set-Cookie':cookie('',0)})}
  if(p==='/api/reports/summary'&&method==='GET'){
   if(u.role!=='admin'&&!u.person_id)return json({error:'Household profile mapping required'},403);
   const row=await env.DB.prepare('SELECT json FROM household_state WHERE id=1').first();
   if(!row)return json({error:'No budget data'},404);
   const s=JSON.parse(row.json),cycle=s.cycles.find(x=>x.id===url.searchParams.get('cycleId'));
   if(!cycle)return json({error:'Pay cycle not found'},404);
   const people=s.people.map(person=>{
    const id=person.id;
    const sums=(xs)=>xs.reduce((n,x)=>n+Number(x.amount||0),0);
    const tx=(cycle.transactions||[]).filter(t=>t.personId===id);
    const estimatedIncome=sums((cycle.incomeEstimates||[]).filter(e=>e.personId===id));
    const actualIncome=sums(tx.filter(t=>t.type==='income'));
    const actualExpenses=sums(tx.filter(t=>t.type==='expense'));
    const budgetedExpenses=s.items.reduce((n,item)=>n+Number(cycle.itemBudgets?.[item.id]?.[id]||0),0);
    const gs=(cycle.paymentGroups||[]).filter(g=>g.personId===id);
    const groupOutstanding=gs.reduce((n,g)=>{
     const total=g.lines.reduce((a,l)=>a+Number(l.amount||0),0);
     const paid=sums(tx.filter(t=>t.batchId===g.id));
     const credited=sums(g.adjustments||[]);
     return n+Math.max(0,total-paid-credited);
    },0);
    return {id,name:person.name,estimatedIncome,actualIncome,budgetedExpenses,actualExpenses,groupOutstanding};
   });
   return json({cycle:{id:cycle.id,name:cycle.name},people});
  }
  if(p==='/api/state'&&method==='GET'){if(u.role!=='admin'&&!u.person_id)return json({error:'Administrator must map this login to a household member'},403);const row=await env.DB.prepare('SELECT json,version FROM household_state WHERE id=1').first();return json(row?{state:u.role==='admin'?JSON.parse(row.json):u.person_id?memberView(JSON.parse(row.json),u.person_id):null,version:row.version}:{state:null,version:0})}
  if(p==='/api/state'&&method==='PUT'){
   const b=await body(req);if(!validState(b?.state)||!Number.isInteger(b?.version))return json({error:'Invalid budget state'},400);
   if(u.role!=='admin'&&!u.person_id)return json({error:'Administrator must map this login to a household member before accessing budget data'},403);
   const current=await env.DB.prepare('SELECT json,version FROM household_state WHERE id=1').first();
   if(u.role!=='admin'&&(!current||current.version!==b.version))return json({error:'Budget was changed. Reload before saving.'},409);
   const next=u.role==='admin'?b.state:safeMemberMerge(JSON.parse(current.json),b.state,u.person_id);
   if(!next)return json({error:'Changes outside your assigned household member are not permitted'},403);
   if(current){
    const original=JSON.parse(current.json);
    for(const closed of original.cycles.filter(x=>x.closed)){
     const submitted=next.cycles.find(x=>x.id===closed.id);
     if(!submitted)return json({error:'Closed cycles cannot be deleted through budget updates'},403);
     if(u.role==='admin'&&!sameJSON(submitted,closed))return json({error:'This pay cycle is closed and cannot be changed. Ask the administrator to reopen it.'},403);
    }
    if(u.role!=='admin'&&original.cycles.some(x=>x.closed!==next.cycles.find(y=>y.id===x.id)?.closed))return json({error:'Only an administrator can close or reopen pay cycles'},403);
   }
   const data=JSON.stringify(next);if(data.length>800000)return json({error:'Budget data exceeds 800KB'},413);
   if(b.version===0){const r=await env.DB.prepare('INSERT OR IGNORE INTO household_state(id,json,version) VALUES(1,?,1)').bind(data).run();if(r.meta.changes)return json({version:1});}
   else {const r=await env.DB.prepare('UPDATE household_state SET json=?,version=version+1,updated_at=CURRENT_TIMESTAMP WHERE id=1 AND version=?').bind(data,b.version).run();if(r.meta.changes)return json({version:b.version+1});}
   return json({error:'Another household member updated the budget. Reload to get the latest data before editing again.'},409);
  }

  if(p==='/api/cycles/status'&&method==='POST'){
   if(u.role!=='admin')return json({error:'Administrator only'},403);
   const b=await body(req);
   if(typeof b?.cycleId!=='string'||typeof b?.closed!=='boolean'||!Number.isInteger(b?.version))return json({error:'Invalid cycle request'},400);
   const row=await env.DB.prepare('SELECT json,version FROM household_state WHERE id=1').first();
   if(!row||row.version!==b.version)return json({error:'Budget changed. Reload and try again'},409);
   const s=JSON.parse(row.json),cycle=s.cycles.find(x=>x.id===b.cycleId);
   if(!cycle)return json({error:'Pay cycle not found'},404);
   cycle.closed=b.closed;
   const result=await env.DB.prepare('UPDATE household_state SET json=?,version=version+1,updated_at=CURRENT_TIMESTAMP WHERE id=1 AND version=?').bind(JSON.stringify(s),row.version).run();
   if(!result.meta.changes)return json({error:'Budget changed. Reload and try again'},409);
   return json({ok:true,version:row.version+1});
  }
  if(p==='/api/cycles/delete'&&method==='POST'){
   if(u.role!=='admin')return json({error:'Administrator only'},403);
   const b=await body(req);
   if(!b||typeof b.cycleId!=='string'||!Number.isInteger(b.version))return json({error:'Invalid deletion request'},400);
   const row=await env.DB.prepare('SELECT json,version FROM household_state WHERE id=1').first();
   if(!row)return json({error:'Budget not initialized'},404);
   if(row.version!==b.version)return json({error:'Budget changed. Reload and retry.'},409);
   const state=JSON.parse(row.json);
   const doomed=state.cycles.find(c=>c.id===b.cycleId);
   if(!doomed)return json({error:'Pay cycle not found'},404);
   if(state.cycles.length<=1)return json({error:'At least one pay cycle must remain'},400);
   state.cycles=state.cycles.filter(c=>c.id!==b.cycleId);
   if(state.currentCycleId===b.cycleId)state.currentCycleId=state.cycles[state.cycles.length-1].id;
   const saved=await env.DB.prepare('UPDATE household_state SET json=?,version=version+1,updated_at=CURRENT_TIMESTAMP WHERE id=1 AND version=?').bind(JSON.stringify(state),row.version).run();
   if(!saved.meta.changes)return json({error:'Budget changed. Reload and retry.'},409);
   return json({ok:true,version:row.version+1,deletedName:doomed.name});
  }
  if(p==='/api/payment-groups/adjust'&&method==='POST'){
   if(u.role!=='admin')return json({error:'Administrator only'},403);
   const b=await body(req);
   if(!b||typeof b.cycleId!=='string'||typeof b.groupId!=='string'||typeof b.date!=='string'||!Number.isFinite(Number(b.amount))||Number(b.amount)<=0||!Number.isInteger(b.version))return json({error:'Invalid adjustment'},400);
   const row=await env.DB.prepare('SELECT json,version FROM household_state WHERE id=1').first();
   if(!row||row.version!==b.version)return json({error:'Budget changed. Reload and try again'},409);
   const s=JSON.parse(row.json),cy=s.cycles.find(c=>c.id===b.cycleId),g=cy?.paymentGroups?.find(x=>x.id===b.groupId);
   if(!g)return json({error:'Payment group not found'},404);
   if(cy.closed)return json({error:'Reopen this cycle before making changes'},403);
   if(b.date<cy.start||b.date>cy.end)return json({error:'Date outside selected pay cycle'},400);
   const total=g.lines.reduce((n,l)=>n+Number(l.amount||0),0);
   const paid=cy.transactions.filter(t=>t.batchId===g.id).reduce((n,t)=>n+Number(t.amount||0),0);
   const adjusted=(g.adjustments||[]).reduce((n,x)=>n+Number(x.amount||0),0);
   const amount=Math.round(Number(b.amount)*100)/100;
   if(amount>Math.max(0,total-paid-adjusted))return json({error:'Adjustment exceeds outstanding group balance'},400);
   (g.adjustments??=[]).push({id:id(),date:b.date,amount,note:String(b.note||'Manual payment credit').slice(0,200)});
   const write=await env.DB.prepare('UPDATE household_state SET json=?,version=version+1,updated_at=CURRENT_TIMESTAMP WHERE id=1 AND version=?').bind(JSON.stringify(s),row.version).run();
   if(!write.meta.changes)return json({error:'Budget changed. Reload and try again'},409);
   return json({ok:true,version:row.version+1});
  }
  if(p==='/api/payment-groups/pay'&&method==='POST'){
   const b=await body(req);if(!b||typeof b.groupId!=='string'||typeof b.accountId!=='string'||typeof b.date!=='string'||!Number.isInteger(b.version))return json({error:'Invalid payment request'},400);
   const row=await env.DB.prepare('SELECT json,version FROM household_state WHERE id=1').first();
   if(!row||row.version!==b.version)return json({error:'Budget changed. Reload before recording payment.'},409);
   const s=JSON.parse(row.json),cycle=s.cycles.find(c=>c.id===b.cycleId),group=cycle?.paymentGroups?.find(g=>g.id===b.groupId);
   if(!group)return json({error:'Payment group not found'},404);
   if(cycle.closed)return json({error:'This pay cycle is closed to transactions'},403);
   if(u.role!=='admin'&&group.personId!==u.person_id)return json({error:'Not permitted'},403);
   if(!s.accounts.some(a=>a.id===b.accountId&&a.personId===group.personId))return json({error:'Select an account belonging to the assigned member'},403);
   if(b.date<cycle.start||b.date>cycle.end)return json({error:'Date outside pay cycle'},400);
   if(cycle.transactions.some(t=>t.batchId===group.id))return json({error:'Group already paid'},409);
   if(!group.lines?.length||group.lines.some(l=>!s.items.some(i=>i.id===l.itemId)||!Number.isFinite(Number(l.amount))||Number(l.amount)<=0))return json({error:'Invalid group allocations'},400);
   const original=group.lines.reduce((n,l)=>n+Math.round(Number(l.amount)*100),0);
   const credits=(group.adjustments||[]).reduce((n,x)=>n+Math.round(Number(x.amount)*100),0);
   if(original<=0||credits<0||credits>original)return json({error:'Invalid group amounts'},400);
   const batchId=id();
   const batch=group.lines.map(l=>({id:id(),batchId:group.id,postingId:batchId,date:b.date,type:'expense',personId:group.personId,accountId:b.accountId,itemId:l.itemId,amount:Math.round(Number(l.amount)*100)/100,label:group.name,note:'Full obligation booked; manual credit is display-only',sourceType:'ach',sourceNickname:String(b.sourceNickname||'').trim().slice(0,80)}));
   cycle.transactions.push(...batch);
   const result=await env.DB.prepare('UPDATE household_state SET json=?,version=version+1,updated_at=CURRENT_TIMESTAMP WHERE id=1 AND version=?').bind(JSON.stringify(s),row.version).run();
   if(!result.meta.changes)return json({error:'Budget changed. Reload and retry'},409);
   return json({ok:true,version:row.version+1,total:batch.reduce((sum,t)=>sum+t.amount,0)});
  }
  if(p==='/api/users'&&method==='GET'){if(u.role!=='admin')return json({error:'Administrator only'},403);const r=await env.DB.prepare('SELECT id,email,display_name name,role,person_id personId FROM users ORDER BY created_at').all();return json({users:r.results})}
  if(p==='/api/users'&&method==='POST'){
   if(u.role!=='admin')return json({error:'Administrator only'},403);const b=await body(req);
   if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(b?.email||'')||String(b?.password||'').length<12||String(b?.password||'').length>256||!String(b?.name||'').trim())return json({error:'Name, valid email and password of at least 12 characters required'},400);
   const salt=hex(bytes(16));try{await env.DB.prepare("INSERT INTO users(id,email,display_name,role,salt,password_hash,iterations) VALUES(?,?,?,'member',?,?,100000)").bind(id(),b.email.toLowerCase().trim(),b.name.trim().slice(0,100),salt,await pbkdf(b.password,salt)).run()}catch{return json({error:'Email already belongs to a household member'},409)}return json({ok:true},201);
  }
  if(p==='/api/users/map'&&method==='POST'){
   if(u.role!=='admin')return json({error:'Administrator only'},403);
   const b=await body(req);
   if(typeof b?.userId!=='string'||typeof b?.personId!=='string')return json({error:'Choose a login and household member'},400);
   const row=await env.DB.prepare('SELECT role FROM users WHERE id=?').bind(b.userId).first();
   if(!row||row.role==='admin')return json({error:'Only member logins can be mapped'},400);
   const current=await env.DB.prepare('SELECT json FROM household_state WHERE id=1').first();
   if(!current||!JSON.parse(current.json).people.some(p=>p.id===b.personId))return json({error:'Household member not found'},400);
   await env.DB.prepare('UPDATE users SET person_id=? WHERE id=? AND role=?').bind(b.personId,b.userId,'member').run();
   return json({ok:true});
  }
  if(p==='/api/password'&&method==='POST'){const b=await body(req);if(!b||String(b.newPassword||'').length<12||String(b.newPassword||'').length>256)return json({error:'New password must have at least 12 characters'},400);const row=await env.DB.prepare('SELECT salt,password_hash,iterations FROM users WHERE id=?').bind(u.id).first();if(await pbkdf(String(b.currentPassword||''),row.salt,row.iterations)!==row.password_hash)return json({error:'Current password incorrect'},403);const salt=hex(bytes(16));await env.DB.prepare('UPDATE users SET salt=?,password_hash=?,iterations=100000 WHERE id=?').bind(salt,await pbkdf(b.newPassword,salt),u.id).run();await env.DB.prepare('DELETE FROM sessions WHERE user_id=? AND token_hash<>?').bind(u.id,await hash(req.headers.get('Cookie')?.match(/hl_session=([a-f0-9]{64})/)?.[1]||'')).run();return json({ok:true})}
  return json({error:'Endpoint not found'},404);
 }catch(e){console.error('API error',e);return json({error:'Server error. Check Worker logs and database migrations.'},500)}
}
export default {fetch:handle};
