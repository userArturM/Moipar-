const recent=new Map();
chrome.runtime.onMessage.addListener((message,sender,sendResponse)=>{
  if(message?.action!=='offer_save')return;
  (async()=>{
    if(!sender.tab||!message.credentials)return;
    const url=new URL(message.url);
    const senderUrl=new URL(sender.url||sender.tab.url);
    if(url.protocol!=='https:'||senderUrl.origin!==url.origin)return;
    const key='offer:'+url.origin;
    const prefs=await chrome.storage.local.get(key);
    if(!prefs[key]||!await chrome.permissions.contains({origins:[url.origin+'/*']}))return;
    const stamp=sender.tab.id+'|'+url.origin+'|'+message.credentials.login;
    if(Date.now()-(recent.get(stamp)||0)<10000)return;
    recent.set(stamp,Date.now());
    if(recent.size>100)recent.delete(recent.keys().next().value);
    try {
      const response=await chrome.runtime.sendNativeMessage('ru.moiparoli.host',
        {action:'save_credentials',url:message.url,credentials:message.credentials});
      chrome.action.setBadgeText({tabId:sender.tab.id,text:response?.ok?'✓':'!'});
      chrome.action.setTitle({tabId:sender.tab.id,title:response?.ok?'Пароль сохранён':'Сохранение отменено или недоступно'});
    } finally {message.credentials.password=''}
  })().catch(()=>{chrome.action.setBadgeText({tabId:sender.tab?.id,text:'!'})}).finally(()=>sendResponse({ok:true}));
  return true;
});
