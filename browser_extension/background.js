const recent=new Map();
const remembered=new Map();
chrome.runtime.onMessage.addListener((message,sender,sendResponse)=>{
  if(!['offer_save','remember_login'].includes(message?.action))return;
  (async()=>{
    if(!sender.tab)return;
    const url=new URL(message.url);
    const senderUrl=new URL(sender.url||sender.tab.url);
    if(url.protocol!=='https:'||senderUrl.origin!==url.origin)return;
    const key='offer:'+url.origin;
    const prefs=await chrome.storage.local.get(key);
    if(!prefs[key]||!await chrome.permissions.contains({origins:[url.origin+'/*']}))return;
    const cacheKey=sender.tab.id+'|'+url.origin;
    for(const [key,data] of remembered)if(Date.now()-data.time>180000)remembered.delete(key);
    if(message.action==='remember_login'){
      if(typeof message.login==='string'&&message.login.length<=1024&&message.login){
        remembered.set(cacheKey,{login:message.login,time:Date.now()});
        if(remembered.size>100)remembered.delete(remembered.keys().next().value);
      }
      return;
    }
    if(!message.credentials||typeof message.credentials.password!=='string')return;
    if(!message.credentials.login)message.credentials.login=remembered.get(cacheKey)?.login||'';
    remembered.delete(cacheKey);
    const stamp=sender.tab.id+'|'+url.origin;
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
