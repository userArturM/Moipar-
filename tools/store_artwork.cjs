// Store compositions use the real popup HTML and bundled icon, with no invented OS dialogs.
const {chromium}=require('playwright');
const fs=require('node:fs');
const path=require('node:path');
(async()=>{
 const root=path.resolve(__dirname,'..');
 const output=path.resolve(process.argv[2]||path.join(root,'store_package'));
 fs.mkdirSync(output,{recursive:true});
 const popup=fs.readFileSync(path.join(root,'browser_extension/popup.html'),'utf8').replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi,'');
 const icon='data:image/png;base64,'+fs.readFileSync(path.join(root,'browser_extension/icon128.png')).toString('base64');
 const browser=await chromium.launch({headless:true,...(process.env.BROWSER_EXE?{executablePath:process.env.BROWSER_EXE}:{})});
 try{
  const page=await browser.newPage({viewport:{width:1280,height:800},deviceScaleFactor:1});
  for(const theme of ['light','dark']){
   await page.emulateMedia({colorScheme:theme});
   await page.setContent(`<!doctype html><meta charset="utf-8"><style>*{box-sizing:border-box}body{margin:0;font:20px 'Segoe UI',sans-serif;color:${theme==='light'?'#1d1d1f':'#f5f5f7'};background:${theme==='light'?'#eef3fb':'#14151a'};width:1280px;height:800px;padding:64px 72px}.brand{display:flex;align-items:center;gap:16px;font-size:22px;font-weight:600}.brand img{width:58px;height:58px}h1{font-size:52px;line-height:1.1;letter-spacing:-2px;width:680px;margin:48px 0 24px}.lead{font-size:23px;line-height:1.55;width:600px;opacity:.75}ol{padding-left:28px;font-size:20px;line-height:2}iframe{position:absolute;top:100px;right:72px;width:360px;height:650px;border:0;border-radius:22px;box-shadow:0 24px 70px #0003;overflow:hidden}.foot{position:absolute;bottom:44px;font-size:17px;opacity:.65}</style><div class="brand"><img src="${icon}">Мои пароли</div><h1>Пароли рядом.<br>Действия — с вашего разрешения.</h1><p class="lead">Сохранение и заполнение через локальное хранилище Windows.</p><ol><li>Выберите действие в расширении</li><li>Подтвердите в приложении</li><li>Проверьте поля перед входом</li></ol><iframe title="Настоящий интерфейс расширения"></iframe><div class="foot">Windows Hello или мастер-пароль · Требуется приложение для Windows</div>`);
   await page.locator('iframe').evaluate((el,html)=>el.srcdoc=html,popup.replace('src="icon48.png"','src="'+icon+'"').replace('Проверка результата…','Результат действия появится здесь.'));
   await page.locator('iframe').contentFrame().locator('#fill').waitFor();
   await page.screenshot({path:path.join(output,`screenshot-${theme}-1280x800.png`)});
  }
  await page.setViewportSize({width:440,height:280});
  await page.setContent(`<!doctype html><meta charset="utf-8"><style>body{margin:0;background:#eef3fb;color:#1d1d1f;font:22px 'Segoe UI';padding:30px}img{width:64px;height:64px;float:right}h1{font-size:34px;line-height:1.1;margin:12px 0 24px;letter-spacing:-1px}p{font-size:18px;line-height:1.5;color:#526079}small{font-size:13px;color:#526079}</style><img src="${icon}"><h1>Мои<br>пароли</h1><p>Локальное хранилище.<br>Заполнение с подтверждением.</p><small>Расширение + приложение Windows</small>`);
  await page.screenshot({path:path.join(output,'promo-440x280.png')});
  fs.copyFileSync(path.join(root,'browser_extension/icon128.png'),path.join(output,'store-icon128.png'));
 }finally{await browser.close()}
})().catch(error=>{console.error(error);process.exitCode=1});
