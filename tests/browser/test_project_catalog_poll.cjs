// Async cached metadata polling: bounded wait, backoff, retry, no duplicate workers.
const assert=require('assert'),fs=require('fs'),vm=require('vm');
let now=100000,timer=null,delay=0,requests=0,rejectRead=false,deferRead=null;
const output={innerHTML:''};
const context={window:{},console,Date:{now:()=>now},document:{hidden:false,addEventListener(){}},filter:'software',controlUpdates:null,esc:String,$:()=>output,renderJobs(){},clock:()=>'',api:async()=>{requests++;if(rejectRead)throw Error('offline');if(deferRead)await deferRead;return{projects:[{custom:true,id:'git-a',name:'A',ok:true,checking:true,sourceUrl:'https://github.com/a/b',releases:[],bindings:{}}]}},setTimeout:(callback,ms)=>{assert.strictEqual(timer,null,'one timer only');timer=callback;delay=ms;return 1},clearTimeout:()=>{timer=null}};
vm.createContext(context);vm.runInContext(fs.readFileSync(require('node:path').join(__dirname,'../../frontend/static/software.js'),'utf8'),context);
vm.runInContext('softwareData={servers:[],components:[{custom:true,id:"git-a",name:"A",ok:true,checking:true,releases:[],bindings:{},sourceUrl:"https://github.com/a/b"}]};',context);
const run=source=>vm.runInContext(source,context),fire=async()=>{const callback=timer;assert(callback);timer=null;now+=delay;await callback()};
(async()=>{
 run('scheduleProjectCatalogRefresh(softwareData.components)');assert.strictEqual(delay,2500);
 for(let i=0;i<4;i++)await fire();assert.strictEqual(delay,10000,'backoff after first four reads');assert.strictEqual(requests,4);
 for(let i=0;i<8;i++)await fire();assert.strictEqual(delay,20000,'backoff to twenty seconds');assert.strictEqual(requests,12);
 now+=15*60*1000;await fire();assert.strictEqual(timer,null);assert.strictEqual(requests,12,'expiry does not perform another read');
 assert(output.innerHTML.includes('ожидание в браузере приостановлено'));assert(output.innerHTML.includes('Перечитать результат'));assert(output.innerHTML.includes('Фоновая задача продолжает работать'));
 run('scheduleProjectCatalogRefresh(softwareData.components)');assert.strictEqual(timer,null,'paused state stays stopped');
 run('resetProjectCatalogProgress()');await run('pollProjectCatalogStatus()');assert.strictEqual(requests,13);assert.strictEqual(delay,2500,'manual retry starts fresh budget');
 // Only one HTTP reader remains active even if the view re-renders meanwhile.
 run('resetProjectCatalogProgress()');let release;deferRead=new Promise(resolve=>release=resolve);
 const pending=run('pollProjectCatalogStatus()');assert.strictEqual(requests,14);await run('pollProjectCatalogStatus()');run('scheduleProjectCatalogRefresh(softwareData.components)');assert.strictEqual(requests,14);assert.strictEqual(timer,null);
 release();await pending;deferRead=null;assert(timer);
 // Hiding / leaving view stops scheduled reads without retrying.
 context.document.hidden=true;await fire();assert.strictEqual(timer,null);assert.strictEqual(requests,14);context.document.hidden=false;
 run('scheduleProjectCatalogRefresh(softwareData.components)');context.filter='servers';await fire();assert.strictEqual(timer,null);assert.strictEqual(requests,14);
 context.filter='software';rejectRead=true;await run('pollProjectCatalogStatus()');assert.strictEqual(requests,15);assert(output.innerHTML.includes('Не удалось прочитать результат'));assert(output.innerHTML.includes('Перечитать результат'));assert.strictEqual(timer,null);
 console.log('Project catalog async polling: 27 assertions passed');
})().catch(error=>{console.error(error);process.exitCode=1});
