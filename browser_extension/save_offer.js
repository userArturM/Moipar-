(()=>{
  if(window.__moiParoliOfferInstalled)return;
  window.__moiParoliOfferInstalled=true;
  function capture(scope=document){return window.MoiParoliCapture?.(scope)}
  let timer;
  document.addEventListener('input',()=>{
    clearTimeout(timer);timer=setTimeout(()=>{
      const data=capture();
      if(data?.credentials.login&&location.protocol==='https:')
        chrome.runtime.sendMessage({action:'remember_login',url:location.href,login:data.credentials.login}).catch(()=>{});
    },200);
  },true);
  function offer(scope){
    const data=capture(scope);
    if(!data?.credentials.password||location.protocol!=='https:')return;
    chrome.runtime.sendMessage({action:'offer_save',...data}).catch(()=>{});
  }
  document.addEventListener('submit',event=>{
    if(event.target instanceof HTMLFormElement)offer(event.target);
  },true);
  document.addEventListener('click',event=>{
    const button=event.target.closest('button,input[type=submit],[role=button]');
    if(!button)return;
    if(button.type==='submit'||/sign.?in|log.?in|register|create account|save password|войти|регистра|сохранить пароль/i.test(button.textContent||button.value||''))
      offer(button.form||document);
  },true);
})();
