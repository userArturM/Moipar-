const passkeyToggle=document.getElementById('passkeys');
if(passkeyToggle){
  const label=document.getElementById('passkeys-status');
  async function refresh(){
    const state=await chrome.runtime.sendMessage({action:'passkeys_status'});
    passkeyToggle.disabled=!state?.available;passkeyToggle.checked=!!state?.enabled;
    label.textContent=state?.permissionRequired?'Включите переключатель, чтобы запросить поддержку у браузера.':state?.available?'Каждое создание и вход требуют подтверждения в Bitora.':'Этот браузер не предоставляет API ключей доступа.';
  }
  passkeyToggle.addEventListener('change',async()=>{
    passkeyToggle.disabled=true;
    try{
      if(passkeyToggle.checked&&!await chrome.permissions.request({permissions:['webAuthenticationProxy']}))throw Error('Разрешение не предоставлено');
      const state=await chrome.runtime.sendMessage({action:passkeyToggle.checked?'passkeys_enable':'passkeys_disable'});
      if(!state?.ok)throw Error(state?.error||'Ключи доступа недоступны');
      await refresh();
    }catch(error){passkeyToggle.checked=false;label.textContent=error.message}
    finally{passkeyToggle.disabled=false}
  });
  refresh().catch(()=>{passkeyToggle.disabled=true;label.textContent='Проверьте поддержку ключей доступа в браузере.'});
}
