const saveButton=document.getElementById('save');
const autoSave=document.getElementById('autosave');
function connectionError(error) {
  const message=error?.message || String(error);
  if (/native messaging host.*not found|host not found/i.test(message))
    return 'Нет связи с приложением. Установите версию 4.5 и откройте «Браузеры → Восстановить подключение».';
  return message;
}
saveButton.addEventListener('click',async()=>{
  if(saveButton.disabled)return;
  saveButton.disabled=true;
  status.textContent='Получение данных страницы…';
  try {
    const [tab]=await chrome.tabs.query({active:true,currentWindow:true});
    const url=new URL(tab.url);
    if(url.protocol!=='https:')throw Error('Откройте HTTPS-страницу с формой входа.');
    const [read]=await chrome.scripting.executeScript({target:{tabId:tab.id},func:()=>{
  function capture(scope=document,remembered='') {
    const fields=[...scope.querySelectorAll('input')].filter(e=>!e.disabled&&e.getClientRects().length>0);
    const has=(e,token)=>e.autocomplete.toLowerCase().split(/\s+/).includes(token);
    const passwords=fields.filter(e=>!has(e,'one-time-code')&&!/otp|verification.?code|auth.?code/i.test(e.name+' '+e.id)&&(e.type==='password'||has(e,'new-password')||has(e,'current-password')));
    const active=passwords.includes(document.activeElement)?document.activeElement:null;
    const pass=passwords.find(e=>has(e,'new-password'))||active||passwords.find(e=>has(e,'current-password'))||
      (new Set(passwords.map(e=>e.value).filter(Boolean)).size<=1?passwords.find(e=>e.value):null);
    const scoped=pass?.form?fields.filter(e=>e.form===pass.form):fields;
    const relevant=scoped.filter(e=>!passwords.includes(e)&&!has(e,'one-time-code')&&!/search|query|otp|verification.?code|auth.?code/i.test(e.name+' '+e.id));
    const login=relevant.find(e=>has(e,'username')||has(e,'email')||e.type==='email')||
      relevant.find(e=>['text','tel'].includes(e.type)&&/user|login|email|identifier|account|phone|mobile/i.test(e.name+' '+e.id))||
      (relevant.filter(e=>e.type==='text'&&!/search/i.test(e.name+' '+e.id)).length===1?
        relevant.find(e=>e.type==='text'&&!/search/i.test(e.name+' '+e.id)):null);
    return {url:location.href,credentials:{title:location.hostname,login:login?.value||remembered,password:pass?.value||''}};
  }

      const data=capture();
      return data.credentials.password?data:null;
    }});
    if(!read?.result)throw Error('Пароль не найден. Заполните форму и нажмите «Сохранить с сайта» перед входом.');
    const latest=await chrome.tabs.get(tab.id);
    if(latest.url!==tab.url||!latest.active||read.result.url!==tab.url)throw Error('Вкладка изменилась. Повторите действие.');
    status.textContent='Подтвердите сохранение в окне приложения…';
    const response=await chrome.runtime.sendMessage({action:'manual_save',tabId:tab.id,...read.result});
    read.result.credentials.password='';
    if(!response?.ok)throw Error(response?.error||'Сохранение не выполнено');
    status.textContent=response.message||'Пароль сохранён';
  }catch(error){status.textContent=connectionError(error)}
  finally{saveButton.disabled=false}
});
document.getElementById('connect').addEventListener('click',async()=>{
  try {
    const response=await chrome.runtime.sendMessage({action:'native_ping'});
    if(!response?.ok)throw Error('Обновите приложение до версии 4.5');
    status.textContent='Приложение подключено · '+response.version;
  }catch(error){status.textContent=connectionError(error)}
});
async function sitePreference(){
  const [tab]=await chrome.tabs.query({active:true,currentWindow:true});
  const url=new URL(tab.url);
  if(url.protocol!=='https:'){autoSave.disabled=true;return}
  const key='offer:'+url.origin;
  const prefs=await chrome.storage.local.get(key);
  autoSave.checked=Boolean(prefs[key]);
  autoSave.addEventListener('change',async()=>{
    const pattern=url.origin+'/*';
    const id='offer-'+url.hostname.replace(/[^a-z0-9]/gi,'-');
    try {
      if(autoSave.checked){
        const granted=await chrome.permissions.request({origins:[pattern]});
        if(!granted){autoSave.checked=false;return}
        await chrome.scripting.unregisterContentScripts({ids:[id]}).catch(()=>{});
        await chrome.scripting.registerContentScripts([{id,js:['form_capture.js','save_offer.js'],matches:[pattern],runAt:'document_idle'}]);
        await chrome.scripting.executeScript({target:{tabId:tab.id},files:['form_capture.js','save_offer.js']});
      } else {
        await chrome.scripting.unregisterContentScripts({ids:[id]}).catch(()=>{});
        await chrome.permissions.remove({origins:[pattern]});
      }
      await chrome.storage.local.set({[key]:autoSave.checked});
      status.textContent=autoSave.checked?'Предложение сохранения включено для этого сайта':'Предложение сохранения отключено';
    }catch(error){autoSave.checked=false;status.textContent=connectionError(error)}
  });
}
sitePreference().catch(()=>{autoSave.disabled=true});
