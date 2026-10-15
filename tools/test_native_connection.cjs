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
    context=await chromium.launchPersistentContext(profile,{...(process.env.BROWSER_EXE?{executablePath:process.env.BROWSER_EXE}:{channel:'chromium'}),headless:process.env.HEADFUL!=='1',ignoreDefaultArgs:['--disable-extensions'],
      args:['--enable-unsafe-extension-debugging']});
    // Branded browsers may ignore --load-extension. Use the browser-level
    // DevTools session; this command is unavailable on a page-level session.
    const devtools=await context.browser().newBrowserCDPSession();
    const loaded=await devtools.send('Extensions.loadUnpacked',{path:extension});
    if(loaded.id!==id)throw new Error('Unexpected extension identity: '+loaded.id);
    const page=await context.newPage();
    await page.goto(`chrome-extension://${id}/popup.html`);
    const response=await page.evaluate(host=>chrome.runtime.sendNativeMessage(host,{action:'ping'}),
      process.env.NATIVE_HOST||'ru.moiparoli.host');
    if(!response.ok||response.version!==(process.env.EXPECT_HOST_VERSION||'4.5.3')||!response.supports.includes('save_credentials'))
      throw new Error('Unexpected installed native host response: '+JSON.stringify(response));
    console.log('Installed extension connected to the real packaged native host: '+response.version);
  } finally {
    if(context)await context.close();
    fs.rmSync(profile,{recursive:true,force:true});
  }
})().catch(error=>{console.error(error);process.exitCode=1});
