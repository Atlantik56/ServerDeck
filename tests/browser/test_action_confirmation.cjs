// Real browser + production dialog scripts/styles; every request is a local fixture.
// No deployed panel, SSH, credentials, reboot, package install or firewall action.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const origin='https://deck.example.test';
const root=path.resolve(__dirname,'../../frontend/static');
const server={id:'one',name:'Demo <VPN> сервер',host:'192.0.2.21',status:{ok:true},services:[]};
const plan=(kind='update')=>({id:'plan-'+kind,server:server.id,host:server.host,summary:{title:'Действие · '+kind,impact:'Изменение выбранного сервера. Подключения могут прерваться.',current:{mtproxyl:'1.7.17'},version:'v1.7.18',warnings:['Проверьте автозапуск VPN.'],steps:['Создать копию','Проверить состояние'],fields:kind==='client'?{enabled:false}:undefined}});
const f2bInfo={name:server.name,host:server.host,editable:true,installed:true,sshPorts:['22'],jails:['sshd'],effective:{maxretry:5,findtime:600,bantime:3600},protectedIgnoreip:['127.0.0.1/8'],controllerIp:'192.0.2.10',pendingJobs:[]};
const f2bPlan={id:'f2b-plan',server:server.id,name:server.name,host:server.host,before:{effective:f2bInfo.effective},settings:{maxretry:6,findtime:600,bantime:3600},effectiveIgnoreip:['127.0.0.1/8'],summary:{title:'Настройка Fail2ban',impact:'Изменится только jail sshd.',preserved:'VPN и действующие исключения сохраняются.',steps:['Создать копию','Проверить jail']}};
const deployment={available:true,canChange:true,busy:false,mode:'domain',host:'old.example.test',origin:'https://old.example.test',email:'admin@example.test',publicIp:'192.0.2.10'};
const deploymentPlan={id:'domain-plan',domain:'new.example.test',oldOrigin:deployment.origin,newOrigin:'https://new.example.test',summary:['Проверить HTTPS','Сохранить настройки']};
const scripts=['control.js','maintenance.js','fail2ban.js','deployment-settings.js'];
const bootstrap=`
 window.$=selector=>document.querySelector(selector);
 window.esc=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 window.state={servers:[${JSON.stringify(server)}],activity:[]};window.filter='all';window.token='fixture-token';
 window.clock=()=>'';window.bytes=String;window.toast=()=>{};window.openSoftware=()=>{};
 window.modal=(title,html)=>{$('#modalTitle').textContent=title;$('#modalBody').innerHTML=html;if(!$('#modal').open)$('#modal').showModal()};
 window.api=async(url,data)=>{const response=await fetch(url,{method:data===undefined?'GET':'POST',headers:{'Content-Type':'application/json'},body:data===undefined?undefined:JSON.stringify(data)});const result=await response.json();if(!response.ok)throw Error(result.error||'Fixture error');return result};
 window.addEventListener('DOMContentLoaded',()=>{$('#closeModal').onclick=()=>$('#modal').close()});
`;
const html=fs.readFileSync(path.join(root,'index.html'),'utf8').replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi,'').replace('</head>',`<script>${bootstrap}</script>${scripts.map(name=>`<script src="/${name}" defer></script>`).join('')}</head>`);

async function waitUntil(predicate,message){
 const end=Date.now()+4000;
 while(!predicate()){if(Date.now()>end)throw Error(message);await new Promise(resolve=>setTimeout(resolve,10))}
}
async function fixture(context){
 const records=[],errors=[],pending=[];let heldPath=null,controlError=false;
 const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));
 await context.route('**/*',async route=>{
  const request=route.request(),url=new URL(request.url());
  assert.equal(url.origin,origin,'Fixture attempted an external request');
  const json=(value,status=200)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(value)});
  if(url.pathname.startsWith('/api/')){
   const data=request.method()==='POST'?request.postDataJSON():undefined;
   records.push({path:url.pathname,data});
   if(url.pathname===heldPath)await new Promise(resolve=>pending.push(resolve));
   if(url.pathname==='/api/control/execute')return json({id:'job',state:'queued'});
   if(url.pathname==='/api/control/acknowledge')return json({ok:true});
   if(url.pathname==='/api/control/plan')return json(plan(data?.kind||'update'));
   if(url.pathname==='/api/control')return json(controlError?{error:'Fixture status temporarily unavailable'}:{jobs:[],backups:[],busyServers:[]},controlError?503:200);
   if(url.pathname==='/api/fail2ban')return json(f2bInfo);
   if(url.pathname==='/api/fail2ban/plan')return json(f2bPlan);
   if(url.pathname==='/api/fail2ban/apply')return json({state:'succeeded',message:'Fixture applied',backup:'/fixture/backup'});
   if(url.pathname==='/api/fail2ban/review')return json({message:'Fixture reviewed'});
   if(url.pathname==='/api/deployment')return json(deployment);
   if(url.pathname==='/api/deployment/plan')return json(deploymentPlan);
   if(url.pathname==='/api/deployment/apply')return json({newOrigin:deploymentPlan.newOrigin,job:{stage:'queued'}});
   throw Error('Unexpected fixture API '+request.method()+' '+url.pathname);
  }
  if(url.pathname==='/')return route.fulfill({contentType:'text/html',body:html});
  const file=path.resolve(root,url.pathname.slice(1));
  if(!file.startsWith(root+path.sep)||!fs.existsSync(file)||!fs.statSync(file).isFile())return route.fulfill({status:404,body:''});
  return route.fulfill({contentType:{'.js':'text/javascript','.css':'text/css','.svg':'image/svg+xml','.png':'image/png','.webmanifest':'application/manifest+json'}[path.extname(file)]||'text/plain',body:fs.readFileSync(file)});
 });
 await page.goto(origin+'/');await page.waitForFunction(()=>typeof showControlPlan==='function'&&typeof window.openFail2ban==='function');
 return {page,records,errors,count:pathname=>records.filter(r=>r.path===pathname).length,hold:pathname=>{heldPath=pathname},release:()=>{heldPath=null;pending.splice(0).forEach(resolve=>resolve())},failControlStatus:value=>{controlError=value}};
}
async function openPlan(page,kind){await page.evaluate(value=>showControlPlan(value),plan(kind));await page.locator('#executeControlForm').waitFor({state:'visible'})}
async function noTypedAddress(page){assert.equal(await page.locator('#modalBody input:not([type="checkbox"]):not([type="hidden"])').count(),0);assert.match(await page.locator('#modalBody').innerText(),/192\.0\.2\.21/);assert.match(await page.locator('#modalBody').innerText(),/Demo <VPN> сервер/)}
async function uncheckedCannotSubmit(f,form,checkbox,submit,endpoint){
 const before=f.count(endpoint);assert.equal(await f.page.locator(checkbox).isChecked(),false);assert.equal(await f.page.locator(submit).isDisabled(),true);
 await f.page.locator(form).evaluate(node=>node.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));
 await f.page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));assert.equal(f.count(endpoint),before,'Unchecked confirmation dispatched a mutation');
}
async function submitOnce(f,form,checkbox,submit,endpoint,expected){
 const before=f.count(endpoint);f.hold(endpoint);await f.page.locator(checkbox).check();assert.equal(await f.page.locator(submit).isEnabled(),true);
 await f.page.locator(submit).click();await waitUntil(()=>f.count(endpoint)===before+1,'Confirmation did not dispatch');
 await f.page.locator(form).evaluate(node=>{node.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}));node.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}))});
 await f.page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
 assert.equal(f.count(endpoint),before+1,'An in-flight confirmation was sent more than once');
 const submitted=f.records.filter(r=>r.path===endpoint).at(-1).data;assert.equal(submitted.confirmation,expected);f.release();
}
async function confirmScenarios(context,width){
 const f=await fixture(context),page=f.page;
 // Installation, client changes and updates share the production preview.
 for(const kind of ['install','client','update']){
  await openPlan(page,kind);await noTypedAddress(page);
  await uncheckedCannotSubmit(f,'#executeControlForm','#controlActionConfirm','#executeControlPlan','/api/control/execute');
  await submitOnce(f,'#executeControlForm','#controlActionConfirm','#executeControlPlan','/api/control/execute',server.host);
  await page.waitForFunction(()=>!document.querySelector('#modal').open);
 }
 await openPlan(page,'restore');const cancelled=f.count('/api/control/execute');await page.locator('#controlActionConfirm').check();await page.locator('#cancelControlPlan').click();assert.equal(f.count('/api/control/execute'),cancelled);
 // A successful dispatch followed by a failed status fetch must not re-arm it.
 await openPlan(page,'update');f.failControlStatus(true);await submitOnce(f,'#executeControlForm','#controlActionConfirm','#executeControlPlan','/api/control/execute',server.host);await page.waitForFunction(()=>!document.querySelector('#modal').open);
 const accepted=f.count('/api/control/execute');await page.locator('#executeControlForm').evaluate(node=>node.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));assert.equal(f.count('/api/control/execute'),accepted);f.failControlStatus(false);
 await page.evaluate(()=>openReboot('one'));await page.locator('#rebootForm').waitFor({state:'visible'});await noTypedAddress(page);assert.match(await page.locator('#modalBody').innerText(),/автозапуск VPN/);
 await uncheckedCannotSubmit(f,'#rebootForm','#rebootConfirm','#rebootSubmit','/api/control/execute');
 if(width<500)assert.equal(await page.locator('#modal').evaluate(node=>node.scrollWidth<=node.clientWidth+1),true,'Mobile confirmation overflows horizontally');
 if(process.env.CONFIRMATION_SCREENSHOT_DIR){fs.mkdirSync(process.env.CONFIRMATION_SCREENSHOT_DIR,{recursive:true});await page.screenshot({path:path.join(process.env.CONFIRMATION_SCREENSHOT_DIR,'reboot-confirmation-'+width+'.png')})}
 await submitOnce(f,'#rebootForm','#rebootConfirm','#rebootSubmit','/api/control/execute',server.host);await page.waitForFunction(()=>!document.querySelector('#modal').open);
 await page.evaluate(()=>{const b=document.createElement('button');b.id='fixtureReview';b.dataset.ctrl='ack-job';b.dataset.job='review-job';b.dataset.server='one';b.dataset.host='192.0.2.21';document.body.append(b);b.click()});await page.locator('#ackControlForm').waitFor({state:'visible'});await noTypedAddress(page);
 await uncheckedCannotSubmit(f,'#ackControlForm','#ackControlConfirm','#ackControlSubmit','/api/control/acknowledge');await submitOnce(f,'#ackControlForm','#ackControlConfirm','#ackControlSubmit','/api/control/acknowledge',server.host);await page.waitForFunction(()=>!document.querySelector('#modal').open);
 await page.evaluate(()=>window.openFail2ban('one'));await page.locator('#f2bForm').waitFor({state:'visible'});await page.locator('[name=maxretry]').fill('6');await page.locator('#f2bPreview').click();await page.locator('#f2bApplyForm').waitFor({state:'visible'});await noTypedAddress(page);
 await uncheckedCannotSubmit(f,'#f2bApplyForm','#f2bConfirm','#f2bApply','/api/fail2ban/apply');await submitOnce(f,'#f2bApplyForm','#f2bConfirm','#f2bApply','/api/fail2ban/apply',server.host);await page.locator('#f2bResultClose').click();
 await page.evaluate(()=>{const b=document.createElement('button');b.dataset.f2bReview='f2b-review';b.dataset.f2bHost='192.0.2.21';b.dataset.f2bName='Demo <VPN> сервер';document.body.append(b);b.click()});await page.locator('#f2bReviewForm').waitFor({state:'visible'});await noTypedAddress(page);
 await uncheckedCannotSubmit(f,'#f2bReviewForm','#f2bReviewConfirm','#f2bReviewSubmit','/api/fail2ban/review');await submitOnce(f,'#f2bReviewForm','#f2bReviewConfirm','#f2bReviewSubmit','/api/fail2ban/review',server.host);await page.waitForFunction(()=>document.querySelector('#modalBody').textContent.includes('Fixture reviewed'));await page.locator('#closeModal').click();
 await page.evaluate(()=>{document.body.classList.add('filter-settings');return window.settingsNavigate('settings')});await page.locator('#deploymentDomainForm').waitFor({state:'visible'});await page.locator('#deploymentDomainForm [name=domain]').fill(deploymentPlan.domain);await page.locator('#deploymentDomainForm button[type=submit]').click();await page.locator('#deploymentConfirmation').waitFor({state:'visible'});
 assert.equal(await page.locator('#deploymentConfirmation').getAttribute('type'),'checkbox');assert.equal(await page.locator('#deploymentConfirmation').isChecked(),false);assert.equal(await page.locator('#deploymentApply').isDisabled(),true);
 await page.locator('#deploymentApply').evaluate(node=>node.click());assert.equal(f.count('/api/deployment/apply'),0);
 f.hold('/api/deployment/apply');await page.locator('#deploymentConfirmation').check();await page.locator('#deploymentApply').click();await waitUntil(()=>f.count('/api/deployment/apply')===1,'Domain confirmation did not dispatch');await page.locator('#deploymentApply').evaluate(node=>{node.click();node.click()});assert.equal(f.count('/api/deployment/apply'),1);assert.equal(f.records.find(r=>r.path==='/api/deployment/apply').data.confirmation,deploymentPlan.domain);f.release();
 await page.waitForFunction(()=>document.querySelector('.deployment-job'));
 assert.deepEqual(f.errors,[],'Browser errors in confirmation fixtures');await page.close();
}
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:process.env.CHROME_BIN||undefined});
 try{for(const width of [1440,393]){const context=await browser.newContext({viewport:{width,height:900},isMobile:width<500,hasTouch:width<500});try{await confirmScenarios(context,width)}finally{await context.close()}}console.log('PASS confirmation UI desktop + 393px: unchecked/cancelled actions blocked, explicit confirmations bound to target, duplicate dispatch blocked, reboot/Fail2ban/review/domain covered.')}finally{await browser.close()}
})().catch(error=>{console.error(error.stack);process.exitCode=1});
