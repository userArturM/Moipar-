(()=>{
  if(window.__moiParoliOfferInstalled)return;
  window.__moiParoliOfferInstalled=true;
  document.addEventListener('submit',event=>{
    const form=event.target;
    if(!(form instanceof HTMLFormElement))return;
    const fields=[...form.querySelectorAll('input')].filter(el=>!el.disabled&&el.getClientRects().length>0);
    const passwords=fields.filter(el=>el.type==='password');
    const pass=fields.find(el=>el.autocomplete==='new-password') ||
      fields.find(el=>el.autocomplete==='current-password') ||
      (passwords.every(el=>el.value===passwords[0]?.value)?passwords[0]:null);
    if(!pass?.value||location.protocol!=='https:')return;
    const login=fields.find(el=>el.autocomplete==='username'||el.type==='email') ||
      fields.find(el=>el.type==='text'&&/user|login|email/i.test(el.name||el.id||''));
    chrome.runtime.sendMessage({action:'offer_save',url:location.href,
      credentials:{title:location.hostname,login:login?.value||'',password:pass.value}}).catch(()=>{});
  },true);
})();
