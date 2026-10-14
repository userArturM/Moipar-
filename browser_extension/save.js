const saveButton=document.getElementById('save');
const autoSave=document.getElementById('autosave');
function connectionError(error) {
  const message=error?.message || String(error);
  if (/native messaging host.*not found|host not found/i.test(message))
    return 'Нет связи с приложением. Установите версию 4.4 и откройте «Браузеры → Восстановить подключение».';
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
      const inputs=[...document.querySelectorAll('input')].filter(el=>!el.disabled&&el.getClientRects().length>0);
      const pass=inputs.find(el=>el.autocomplete==='new-password') ||
        inputs.find(el=>el.autocomplete==='current-password') || inputs.find(el=>el.type==='password');
      if(!pass?.value)return null;
      const form=pass.form;
      const relevant=form?inputs.filter(el=>el.form===form):inputs;
      const login=relevant.find(el=>el.autocomplete==='username'||el.type==='email') ||
        relevant.find(el=>el.type==='text'&&/user|login|email/i.test(el.name||el.id||''));
      return {url:location.href,credentials:{title:location.hostname,login:login?.value||'',password:pass.value}};
    }});
    if(!read?.result)throw Error('Пароль не найден. Заполните форму и нажмите «Сохранить с сайта» перед входом.');
    const latest=await chrome.tabs.get(tab.id);
    if(latest.url!==tab.url||!latest.active||read.result.url!==tab.url)throw Error('Вкладка изменилась. Повторите действие.');
    status.textContent='Подтвердите сохранение в окне приложения…';
    const response=await chrome.runtime.sendNativeMessage('ru.moiparoli.host',{action:'save_credentials',...read.result});
    read.result.credentials.password='';
    if(!response?.ok)throw Error(response?.error||'Сохранение не выполнено');
    status.textContent=response.message||'Пароль сохранён';
  }catch(error){status.textContent=connectionError(error)}
  finally{saveButton.disabled=false}
});
document.getElementById('connect').addEventListener('click',async()=>{
  try {
    const response=await chrome.runtime.sendNativeMessage('ru.moiparoli.host',{action:'ping'});
    if(!response?.ok)throw Error('Обновите приложение до версии 4.4');
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
        await chrome.scripting.registerContentScripts([{id,js:['save_offer.js'],matches:[pattern],runAt:'document_idle'}]);
        await chrome.scripting.executeScript({target:{tabId:tab.id},files:['save_offer.js']});
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
