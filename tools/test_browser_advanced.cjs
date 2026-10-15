const {chromium}=require('playwright');
const fs=require('fs');
const assert=require('assert/strict');
const vm=require('vm');
(async()=>{
  const browser=await chromium.launch({headless:true,...(process.env.BROWSER_EXE?{executablePath:process.env.BROWSER_EXE}:{})});
  try{
    const page=await browser.newPage();
    await page.route('https://example.test/**',route=>route.fulfill({contentType:'text/html',body:'<main></main>'}));
    await page.goto('https://example.test/login');
    const capture=fs.readFileSync('browser_extension/form_capture.js','utf8');
    async function fill(){
      const button={disabled:false,addEventListener:(_,fn)=>button.handler=fn};
      const status={textContent:''};
      const chrome={tabs:{query:async()=>[{id:1,url:page.url()}],get:async()=>({active:true,url:page.url()})},
        runtime:{sendNativeMessage:async()=>({ok:true,login:'chosen@example.test',password:'StoredFake!789'})},
        scripting:{executeScript:async({func,args})=>[{result:await page.evaluate('('+func.toString()+')(...'+JSON.stringify(args)+')')}]}};
      vm.runInNewContext(fs.readFileSync('browser_extension/popup.js','utf8'),{document:{getElementById:id=>id==='fill'?button:status},chrome,URL});
      await button.handler();
    }
    await page.addScriptTag({content:capture});
    await page.setContent('<form><input autocomplete="section-main username" value="artur"><input type="password" autocomplete="current-password" value="OldFake!789"><input type="password" autocomplete="section-main new-password" value="NewFake!789"><input type="password" autocomplete="new-password" value="NewFake!789"></form>');
    let read=await page.evaluate(()=>window.MoiParoliCapture());
    assert.equal(read.credentials.login,'artur');assert.equal(read.credentials.password,'NewFake!789');
    await page.setContent('<form><input type=password value=FirstFake></form><form><input type=password value=SecondFake></form>');
    assert.equal((await page.evaluate(()=>window.MoiParoliCapture())).credentials.password,'');
    await page.setContent('<input name=identifier value="first-step@example.test"><button type=button>Next</button>');
    assert.equal((await page.evaluate(()=>window.MoiParoliCapture())).credentials.login,'first-step@example.test');
    await page.setContent('<input type=password autocomplete=current-password value="SecondStepFake!789">');
    read=await page.evaluate(()=>window.MoiParoliCapture(document,'first-step@example.test'));
    assert.equal(read.credentials.login,'first-step@example.test');assert.equal(read.credentials.password,'SecondStepFake!789');
    await page.setContent('<input type=email value="new@example.test"><input type=password autocomplete=new-password value="RegisterFake!789"><button type=button>Регистрация</button>');
    await page.evaluate(()=>{window.sent=[];window.chrome=window.chrome||{};window.chrome.runtime={sendMessage:async m=>window.sent.push(m)}});
    await page.addScriptTag({content:fs.readFileSync('browser_extension/save_offer.js','utf8')});
    await page.locator('button').click();
    const sent=await page.evaluate(()=>window.sent);
    assert.equal(sent[0].action,'offer_save');assert.equal(sent[0].credentials.password,'RegisterFake!789');
    await page.setContent('<input id=identifier autocomplete=username>');await fill();
    assert.equal(await page.locator('input').inputValue(),'chosen@example.test');
    await page.setContent('<input id=old type=password autocomplete=current-password><input id=new type=password autocomplete=new-password>');await fill();
    assert.equal(await page.locator('#old').inputValue(),'StoredFake!789');assert.equal(await page.locator('#new').inputValue(),'');
    await page.setContent('<input id=otp type=tel autocomplete=one-time-code>');await fill();
    assert.equal(await page.locator('input').inputValue(),'');
    await page.setContent('<input id=visiblePassword type=text autocomplete=current-password value="ShownFake!789">');
    read=await page.evaluate(()=>window.MoiParoliCapture());
    assert.equal(read.credentials.password,'ShownFake!789');assert.equal(read.credentials.login,'');
    console.log('Advanced forms passed: registration, password change, ambiguous forms, two-step username, JavaScript button');
  } finally {await browser.close()}
})().catch(error=>{console.error(error);process.exitCode=1});
