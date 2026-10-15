const {chromium}=require('playwright');
const fs=require('fs');
const assert=require('assert/strict');
(async()=>{
  const browser=await chromium.launch({headless:true,...(process.env.BROWSER_EXE?{executablePath:process.env.BROWSER_EXE}:{})});
  try{
    const page=await browser.newPage();
    await page.route('https://example.test/**',route=>route.fulfill({contentType:'text/html',body:'<main></main>'}));
    await page.goto('https://example.test/login');
    const capture=fs.readFileSync('browser_extension/form_capture.js','utf8');
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
    console.log('Advanced forms passed: registration, password change, ambiguous forms, two-step username, JavaScript button');
  } finally {await browser.close()}
})().catch(error=>{console.error(error);process.exitCode=1});
