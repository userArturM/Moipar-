// Isolated browser + synthetic relying party. OS approval alone is stubbed.
const fs=require('node:fs');
const path=require('node:path');
const http=require('node:http');
const https=require('node:https');
const {execFileSync}=require('node:child_process');
const assert=require('node:assert/strict');
const {chromium}=require('playwright');
const root=path.resolve('test_temp/passkey-browser');fs.mkdirSync(root,{recursive:true});
const profile=fs.mkdtempSync(path.join(root,'profile-'));
const fixture=fs.mkdtempSync(path.join(root,'vault-'));
const extension=fs.mkdtempSync(path.join(root,'extension-'));
function backend(action,message){
  return JSON.parse(execFileSync(process.env.PYTHON_EXE,[path.resolve('tools/passkey_fixture.py'),fixture,action],
    {input:message?JSON.stringify(message):undefined,encoding:'utf8',windowsHide:true}));
}
(async()=>{
 const server=http.createServer((req,res)=>{
  if(req.method==='GET'){res.setHeader('Content-Type','text/html');res.end('<button id="run">Synthetic WebAuthn</button>');return}
  let body='';req.on('data',chunk=>{body+=chunk});req.on('end',()=>{
   try{const message=JSON.parse(body);const result=backend(message.action.replace('passkey_',''),message);
    res.setHeader('Content-Type','application/json');res.end(JSON.stringify(result));}
   catch(error){res.statusCode=500;res.end(JSON.stringify({ok:false,error:'Synthetic test failed'}));}
  });
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const endpoint='http://127.0.0.1:'+server.address().port+'/';
 fs.writeFileSync(path.join(extension,'manifest.json'),JSON.stringify({manifest_version:3,name:'Bitora synthetic WebAuthn test',version:'1.0',
  permissions:['webAuthenticationProxy','storage','nativeMessaging'],host_permissions:[endpoint+'*'],background:{service_worker:'worker.js'}}));
 const source=fs.readFileSync('browser_extension/passkeys_worker.js','utf8');
 const mock=`chrome.runtime.connectNative=()=>{const listeners=[],closed=[];let ended=false;const abort=new AbortController();
 return {onMessage:{addListener:f=>listeners.push(f)},onDisconnect:{addListener:f=>closed.push(f)},
 disconnect(){if(!ended){ended=true;abort.abort();closed.forEach(f=>f())}},
 postMessage(message){fetch(${JSON.stringify(endpoint)},{method:'POST',body:JSON.stringify(message),signal:abort.signal}).then(r=>r.json()).then(v=>{if(!ended)listeners.forEach(f=>f(v))}).catch(()=>{})}};};\n`;
 fs.writeFileSync(path.join(extension,'worker.js'),mock+source);
 let context;
 try{
  context=await chromium.launchPersistentContext(profile,{headless:true,executablePath:process.env.BROWSER_EXE,channel:process.env.BROWSER_EXE?undefined:'chromium',
   args:[`--disable-extensions-except=${extension}`,`--load-extension=${extension}`,'--disable-features=DisableLoadExtensionCommandLineSwitch','--no-proxy-server']});
  let worker=context.serviceWorkers()[0]||await context.waitForEvent('serviceworker',{timeout:20000});
  const available=await worker.evaluate(()=>Boolean(chrome.webAuthenticationProxy));
  assert(available,'Browser does not expose WebAuthenticationProxy in this test session');
  await worker.evaluate(()=>bitoraPasskeys.control('passkeys_enable'));
  const page=await context.newPage();
  await page.goto('http://localhost:'+server.address().port+'/');
  await page.waitForSelector('#run',{timeout:5000}).catch(async error=>{throw Error('Synthetic page: '+await page.title()+' '+(await page.locator('body').innerText()).slice(0,240))});
  for(const operation of ['create','get']){
   const options=backend('options_'+operation).publicKey;
   await page.evaluate(({operation,options})=>{
    window.fixtureResult=null;window.fixtureError=null;
    document.getElementById('run').onclick=async()=>{
     try{const publicKey=operation==='create'?PublicKeyCredential.parseCreationOptionsFromJSON(options):PublicKeyCredential.parseRequestOptionsFromJSON(options);
      const response=await navigator.credentials[operation]({publicKey});window.fixtureResult=response.toJSON();}
     catch(error){window.fixtureError=error.name+': '+error.message;}
    };
   },{operation,options});
   await page.locator('#run').click();
   await page.waitForFunction(()=>window.fixtureResult||window.fixtureError,{},{timeout:45000});
   const response=await page.evaluate(()=>({result:window.fixtureResult,error:window.fixtureError}));
   assert(!response.error,response.error);
   assert.equal(backend('verify_'+operation,response.result).ok,true);
  }
  await worker.evaluate(()=>bitoraPasskeys.control('passkeys_disable'));
  console.log('Real browser WebAuthn registration and assertion verified by independent FIDO2 server; isolated synthetic vault, OS consent stubbed.');
 }finally{if(context)await context.close();await new Promise(resolve=>server.close(resolve));}
})().catch(error=>{console.error(error);process.exitCode=1});
