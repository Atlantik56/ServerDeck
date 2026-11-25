// The real updater UI against a fixture that stops and rotates the page token.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');

const origin='https://deck.example.test';
const staticRoot=path.resolve(__dirname,'../../frontend/static');
const firstToken='a'.repeat(43);
const secondToken='b'.repeat(43);
const installed='1.6.0';
const latest='1.6.1';
const releaseURL='https://github.com/Atlantik56/ServerDeck/releases/tag/v'+latest;
const shell=fs.readFileSync(path.join(staticRoot,'index.html'),'utf8').replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi,'');
const bootstrap=`
const esc=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const token=document.querySelector('meta[name="deck-token"]').content;
async function api(url,data){
 const headers={'X-Deck-Token':token,'Content-Type':'application/json'};
 const response=await fetch(url,data?{method:'POST',body:JSON.stringify(data),headers}:{headers});
 const value=await response.json();
 if(!response.ok)throw Error(value.error);
 return value;
}
function modal(title,body){
 document.querySelector('#modalTitle').textContent=title;
 document.querySelector('#modalBody').innerHTML=body;
 document.querySelector('#modal').showModal();
}
document.addEventListener('click',event=>{
 if(event.target.closest('aside [data-filter="updates"]'))document.body.classList.add('filter-updates');
});
`;

async function run(browser) {
 const context=await browser.newContext({viewport:{width:390,height:820},isMobile:true,hasTouch:true});
 try{
  const page=await context.newPage();
  const errors=[],posts=[];
  let restarted=false,checks=0,oldPolls=0,documents=0;
  page.on('pageerror',error=>errors.push(error.message));
  await context.route('**/*',async route=>{
   const req=route.request(),url=new URL(req.url());
   assert.equal(url.origin,origin);
   if(url.pathname==='/api/panel-update/apply'){
    assert.equal(req.method(),'POST');
    posts.push(req.postDataJSON());
    restarted=true;
    return route.fulfill({json:{accepted:true,job:{state:'queued',stage:'queued',version:latest}}});
   }
   if(url.pathname==='/api/panel-update'){
    if(restarted&&req.headers()['x-deck-token']!==secondToken){
     oldPolls++;
     return route.fulfill({status:403,json:{error:'Откройте панель заново'}});
    }
    if(url.searchParams.get('force')==='1')checks++;
    return route.fulfill({json:{
     supported:true,installed:{version:restarted?latest:installed,revision:'0123456789abcdef'},
     latest:{version:latest,url:releaseURL,summary:'<img src=x> Фиктивное изменение'},
     state:restarted?'current':'available',checkedAt:1800000000,
     job:restarted?{state:'succeeded',stage:'complete',version:latest}:null,
    }});
   }
   if(url.pathname==='/'){
    if(req.isNavigationRequest())documents++;
    const pageHTML=shell.replace('__TOKEN__',restarted?secondToken:firstToken)
     .replace('</head>',`<script>${bootstrap}</script><script src="/panel-updates.js" defer></script></head>`);
    return route.fulfill({contentType:'text/html; charset=utf-8',body:pageHTML});
   }
   const file=path.join(staticRoot,url.pathname.slice(1));
   if(fs.existsSync(file)&&fs.statSync(file).isFile()&&/\.(js|css)$/.test(file)){
    return route.fulfill({contentType:file.endsWith('.js')?'text/javascript':'text/css',body:fs.readFileSync(file)});
   }
   return route.fulfill({status:404,body:''});
  });

  await page.goto(origin);
  const banner=page.locator('#panelUpdatesBanner');
  const card=page.locator('#panelUpdatesCard');
  await banner.getByRole('button',{name:'Открыть обновления'}).click();
  await card.getByRole('button',{name:'Проверить релизы GitHub'}).click();
  await card.getByRole('button',{name:`Установить ${latest}…`}).click();
  assert.equal(checks,1);
  assert.equal(await card.getByRole('link',{name:/Релиз на GitHub/}).getAttribute('href'),releaseURL);
  const checkbox=page.locator('#panelUpdateConfirm');
  const submit=page.locator('#panelUpdateSubmit');
  const form=page.locator('#panelUpdateConfirmForm');
  assert.equal(await checkbox.isChecked(),false);
  assert.equal(await submit.isDisabled(),true);
  assert.equal(await form.locator('img').count(),0);
  await form.evaluate(node=>node.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));
  assert.equal(posts.length,0);
  await checkbox.check();
  await submit.click();
  await card.getByText('Обновление установлено').waitFor({state:'visible',timeout:12000});
  await banner.waitFor({state:'hidden'});
  assert.deepEqual(posts,[{version:latest}]);
  assert.equal(oldPolls,1);
  assert.equal(documents,2);
  assert.deepEqual(errors,[]);
 }finally{await context.close()}
}

(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:process.env.CHROME_BIN||undefined});
 try{await run(browser);console.log('PASS panel update confirmation and restart recovery')}
 finally{await browser.close()}
})().catch(error=>{console.error(error.stack);process.exitCode=1});
