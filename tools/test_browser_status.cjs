// Real popup DOM with synthetic transport responses; no native authentication.
const {chromium}=require('playwright');
const fs=require('node:fs');
const path=require('node:path');
const assert=require('node:assert/strict');
(async()=>{
 const root=path.resolve(__dirname,'..');
 const browser=await chromium.launch({headless:true,...(process.env.BROWSER_EXE?{executablePath:process.env.BROWSER_EXE}:{})});
 try{
  const version=JSON.parse(fs.readFileSync(path.join(root,'browser_extension/manifest.json'),'utf8')).version;
  for(const theme of ['light','dark']){
   const page=await browser.newPage({viewport:{width:360,height:900},colorScheme:theme});
   await page.addInitScript(({version})=>{
    window.chrome={runtime:{getManifest:()=>({version}),sendMessage:async request=>{
     if(request.action==='last_result')return {ok:true,result:{state:'success',message:'Пароль сохранён',time:Date.now()}};
     if(request.action==='native_ping')return {ok:true,version,supports:['save_credentials','get_credentials']};
    }},tabs:{query:async()=>[{id:1,url:'https://example.test/login'}]},storage:{local:{get:async()=>({})}}};
   },{version});
   await page.route('https://popup.test/**',route=>{
    const name=new URL(route.request().url()).pathname.slice(1)||'popup.html';
    const file=path.join(root,'browser_extension',name);
    return route.fulfill({path:file});
   });
   await page.goto('https://popup.test/popup.html');
   await page.waitForFunction(()=>document.getElementById('last-result').dataset.state==='success');
   assert.match(await page.locator('#last-result').innerText(),/Пароль сохранён/);
   await page.locator('summary').click();await page.locator('#connect').click();
   await page.waitForFunction(()=>document.getElementById('connection-details').textContent.includes('Версии совпадают'));
   assert.match(await page.locator('#connection-details').innerText(),/Сохранение и заполнение поддерживаются/);
   assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
   const output=process.env.STATUS_SCREENSHOTS;
   if(output){fs.mkdirSync(output,{recursive:true});await page.screenshot({path:path.join(output,`extension-${theme}.png`),fullPage:true})}
   await page.close();
  }
  console.log('Popup DOM passed: remembered operation, version diagnostics, light/dark layout, no horizontal overflow.');
 }finally{await browser.close()}
})().catch(error=>{console.error(error);process.exitCode=1});
