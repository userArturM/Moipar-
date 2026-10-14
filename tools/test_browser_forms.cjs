// Real Chromium DOM tests with synthetic accounts; native consent is stubbed.
const fs=require('node:fs');
const vm=require('node:vm');
const assert=require('node:assert/strict');
const {chromium}=require('playwright');
(async()=>{
  const options={headless:true};
  if(process.env.BROWSER_EXE) options.executablePath=process.env.BROWSER_EXE;
  const browser=await chromium.launch(options);
  try {
    const page=await browser.newPage();
    await page.route('https://example.test/**',route=>route.fulfill({
      contentType:'text/html',body:'<form onsubmit="window.submitted=true;return false"><input type="text" hidden><input id="user" autocomplete="username"><input id="password" type="password"><button>Submit</button></form><iframe srcdoc="<input type=password>"></iframe>'}));
    const source=fs.readFileSync('browser_extension/popup.js','utf8');
    for(const scenario of ['fill','cancel','navigation','second-account']){
      await page.goto('https://example.test/login');
      let handler;
      const status={textContent:''};
      const button={disabled:false,addEventListener:(_,fn)=>handler=fn};
      const chosen=scenario==='second-account'?'selected-account':'test-account';
      const chrome={
        tabs:{query:async()=>[{id:1,url:page.url()}],get:async()=>({active:true,url:scenario==='navigation'?'https://other.test/':page.url()})},
        runtime:{sendNativeMessage:async()=>scenario==='cancel'?{ok:false,error:'Canceled'}:{ok:true,login:chosen,password:'FakePassword!789'}},
        scripting:{executeScript:async({func,args})=>[{result:await page.evaluate('('+func.toString()+')(...'+JSON.stringify(args)+')')}]}
      };
      vm.runInNewContext(source,{document:{getElementById:id=>id==='fill'?button:status},chrome,URL});
      await handler();
      const values=await page.locator('input').evaluateAll(nodes=>nodes.map(el=>el.value));
      assert.equal(values[0],'');
      assert.equal(values[1],['fill','second-account'].includes(scenario)?chosen:'');
      assert.equal(values[2],['fill','second-account'].includes(scenario)?'FakePassword!789':'');
      assert.equal(await page.evaluate(()=>Boolean(window.submitted)),false);
      assert.equal(await page.frames()[1].locator('input').inputValue(),'');
    }
    console.log('Real browser DOM tests passed: visible fields, selected account, cancellation, changed tab, iframe exclusion, no submit');
  } finally {await browser.close();}
})().catch(error=>{console.error(error);process.exit(1)});
