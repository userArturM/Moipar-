const {chromium}=require('playwright');
const fs=require('fs');
const os=require('os');
const path=require('path');
(async()=>{
  const extension=path.resolve(process.argv[2]);
  const id=fs.readFileSync(path.join(extension,'extension_id.txt'),'utf8').trim();
  const profile=fs.mkdtempSync(path.join(os.tmpdir(),'moiparoli-browser-'));
  let context;
  try {
    context=await chromium.launchPersistentContext(profile,{channel:'chromium',headless:true,
      args:[`--disable-extensions-except=${extension}`,`--load-extension=${extension}`]});
    const page=await context.newPage();
    await page.goto(`chrome-extension://${id}/popup.html`);
    const response=await page.evaluate(()=>chrome.runtime.sendNativeMessage('ru.moiparoli.host',{action:'ping'}));
    if(!response.ok||response.version!=='4.4'||!response.supports.includes('save_credentials'))
      throw new Error('Unexpected installed native host response: '+JSON.stringify(response));
    console.log('Installed extension connected to the real packaged native host: 4.4');
  } finally {
    if(context)await context.close();
    fs.rmSync(profile,{recursive:true,force:true});
  }
})().catch(error=>{console.error(error);process.exitCode=1});
