importScripts('fill.js');
const recent=new Map();
const remembered=new Map();
const pending=new Map();
function trustedPopup(sender){
  return sender.id===chrome.runtime.id&&sender.url===chrome.runtime.getURL('popup.html');
}
function manualStatus(message,sender,ok){
  if(!trustedPopup(sender)||!Number.isInteger(message.tabId))return;
  chrome.action.setBadgeText({tabId:message.tabId,text:ok?'✓':'!'});
  chrome.action.setTitle({tabId:message.tabId,title:ok?'Действие выполнено':'Действие отменено или недоступно'});
}
function nativeRequest(message){
  return new Promise((resolve,reject)=>{
    const port=chrome.runtime.connectNative('ru.moiparoli.host');
    let done=false;
    port.onMessage.addListener(reply=>{if(done)return;done=true;resolve(reply);port.disconnect()});
    port.onDisconnect.addListener(()=>{if(done)return;done=true;reject(Error(chrome.runtime.lastError?.message||'Соединение с приложением закрыто'))});
    port.postMessage(message);
  });
}
async function manualRequest(message,sender){
  if(!trustedPopup(sender))
    throw Error('Запрос разрешён только из окна расширения');
  if(message.action==='native_ping')return nativeRequest({action:'ping'});
  if(!Number.isInteger(message.tabId)||typeof message.url!=='string')throw Error('Неверная вкладка');
  const url=new URL(message.url);
  if(url.protocol!=='https:')throw Error('Поддерживаются только HTTPS-сайты.');
  const tab=await chrome.tabs.get(message.tabId);
  if(!tab.active||tab.url!==message.url)throw Error('Вкладка изменилась — запрос отменён.');
  if(pending.has(tab.id))throw Error('Для этой вкладки уже открыто подтверждение');
  pending.set(tab.id,true);
  let reply;
  try{
    if(message.action==='manual_save'){
      if(!message.credentials||typeof message.credentials.password!=='string')throw Error('Нет данных для сохранения');
      reply=await nativeRequest({action:'save_credentials',url:message.url,credentials:message.credentials});
      return reply?.ok?{ok:true,message:reply.message||'Пароль сохранён'}:{ok:false,error:reply?.error||'Сохранение отменено'};
    }
    reply=await nativeRequest({action:'get_credentials',url:message.url});
    if(!reply?.ok)return {ok:false,error:reply?.error||'Заполнение отменено'};
    const latest=await chrome.tabs.get(tab.id);
    if(!latest.active||latest.url!==message.url)throw Error('Вкладка изменилась — запрос отменён.');
    const filled=await chrome.scripting.executeScript({target:{tabId:tab.id},func:MoiParoliFill,
      args:[reply.login,reply.password,url.origin]});
    return filled?.[0]?.result?{ok:true,message:'Поля заполнены. Проверьте сайт перед входом.'}:
      {ok:false,error:'Форма пароля не найдена.'};
  }finally{
    if(reply&&'password' in reply)reply.password='';
    if(message.credentials)message.credentials.password='';
    pending.delete(tab.id);
  }
}
chrome.runtime.onMessage.addListener((message,sender,sendResponse)=>{
  if(['manual_fill','manual_save','native_ping'].includes(message?.action)){
    manualRequest(message,sender).then(reply=>{
      manualStatus(message,sender,reply.ok);
      sendResponse(reply);
    }).catch(error=>{
      manualStatus(message,sender,false);
      sendResponse({ok:false,error:error.message});
    });
    return true;
  }
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
