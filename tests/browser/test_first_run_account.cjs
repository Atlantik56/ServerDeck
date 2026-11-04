// Browser fixtures only; no deployed panel, credentials or external request.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const origin='https://192.0.2.10:34871', claim='c'.repeat(43), password='fixture-first-password';
const root=path.resolve(__dirname,'../../frontend/pwa');
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:process.env.CHROME_BIN||undefined});
 try{
  for(const width of [1440,393,360]){
   const context=await browser.newContext({viewport:{width,height:900},isMobile:width<500,hasTouch:width<500});
   const problems=[],submitted=[];let ready=true, reject=true;
   const page=await context.newPage();page.on('pageerror',error=>problems.push(error.message));
   await context.route('**/*',async route=>{
    const request=route.request(), url=new URL(request.url());assert.equal(url.origin,origin);
    if(url.pathname==='/auth/setup'){
     if(request.method()==='GET')return route.fulfill({contentType:'application/json',body:JSON.stringify({required:true,available:ready,error:ready?undefined:'Fixture expired setup code'})});
     submitted.push(request.postDataJSON());
     if(reject)return route.fulfill({status:401,contentType:'application/json',body:JSON.stringify({error:'<img src=x onerror=alert(1)> Wrong claim code'})});
     return route.fulfill({contentType:'application/json',body:JSON.stringify({ok:true,username:'chosen-user'})});
    }
    if(url.pathname==='/')return route.fulfill({contentType:'text/html',body:'<h1>Fixture dashboard</h1>'});
    if(url.pathname==='/auth/session')return route.fulfill({status:401,contentType:'application/json',body:'{}'});
    const relative=url.pathname==='/login/'?'login/index.html':url.pathname.slice(1), file=path.resolve(root,relative);
    if(!file.startsWith(root+path.sep)||!fs.existsSync(file)||!fs.statSync(file).isFile())return route.fulfill({status:404,body:''});
    const contentType={'.html':'text/html','.js':'text/javascript','.css':'text/css','.png':'image/png','.svg':'image/svg+xml','.webmanifest':'application/manifest+json'}[path.extname(file)];
    return route.fulfill({contentType,body:fs.readFileSync(file)});
   });
   await page.goto(origin+'/login/');await page.locator('#setupForm').waitFor({state:'visible'});
   assert.equal(await page.locator('#loginForm').isVisible(),false);
   assert.equal(await page.locator('#setupPassword').getAttribute('autocomplete'),'new-password');
   assert.equal(await page.locator('#setupCode').getAttribute('autocomplete'),'off');
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
   await page.locator('#setupCode').fill(claim);await page.locator('#setupUsername').fill('chosen-user');
   await page.locator('#setupPassword').fill(password);await page.locator('#setupConfirm').fill(password+'different');await page.locator('#setupSubmit').click();
   assert.match(await page.locator('#setupError').innerText(),/не совпадают/);assert.equal(submitted.length,0);
   await page.locator('#setupPassword').fill('я'.repeat(37));await page.locator('#setupConfirm').fill('я'.repeat(37));await page.locator('#setupSubmit').click();
   assert.match(await page.locator('#setupError').innerText(),/72/);assert.equal(submitted.length,0);
   await page.locator('#setupPassword').fill(password);await page.locator('#setupConfirm').fill(password);await page.locator('#setupRemember').check();await page.locator('#setupSubmit').click();
   await page.waitForFunction(()=>document.getElementById('setupError').textContent.includes('Wrong claim'));
   assert.equal(await page.locator('#setupError img').count(),0);assert.match(await page.locator('#setupError').innerText(),/<img/);
   assert.equal(submitted.length,1);assert.equal(submitted[0].code,claim);assert.equal(submitted[0].username,'chosen-user');
   assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length),0);
   reject=false;await page.locator('#setupSubmit').click();await page.waitForURL(origin+'/');
   assert.equal(submitted.length,2);assert.equal(submitted[1].remember,true);
   ready=false;await page.goto(origin+'/login/');await page.locator('#setupForm').waitFor({state:'visible'});
   assert.equal(await page.locator('#setupSubmit').isDisabled(),true);assert.match(await page.locator('#setupError').innerText(),/expired/);
   assert.deepEqual(problems,[]);await context.close();
  }
  process.stdout.write('PASS first-run UI desktop, 393px and 360px: account selection, mismatch, UTF-8 limit, claim errors escaped, no browser storage, expired claim, navigation.\n');
 }finally{await browser.close()}
})().catch(error=>{process.stderr.write(error.stack+'\n');process.exitCode=1});
