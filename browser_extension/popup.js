const status=document.getElementById('status');
const fillButton=document.getElementById('fill');
fillButton.addEventListener('click',async()=>{
  if(fillButton.disabled)return;
  fillButton.disabled=true;
  status.textContent='Подтвердите действие в окне приложения. Можно использовать Windows Hello.';
  try{
    const [tab]=await chrome.tabs.query({active:true,currentWindow:true});
    if(new URL(tab.url).protocol!=='https:')throw Error('Поддерживаются только HTTPS-сайты.');
    const reply=await chrome.runtime.sendMessage({action:'manual_fill',tabId:tab.id,url:tab.url});
    if(!reply?.ok)throw Error(reply?.error||'Нет ответа от приложения');
    status.textContent=reply.message;
  }catch(error){status.textContent=typeof connectionError==='function'?connectionError(error):error.message}
  finally{fillButton.disabled=false}
});
