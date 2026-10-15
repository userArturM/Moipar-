// Component-test adapter: run the actual worker with a mocked native transport.
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
module.exports=function bindWorker(chrome){
 const native=chrome.runtime.sendNativeMessage;
 const id='odddlefcmbmjphfnglidnmdpdlofmfgn';
 let listener;
 const runtime=chrome.runtime;
 runtime.id=id;
 runtime.getURL=p=>`chrome-extension://${id}/${p}`;
 runtime.onMessage={addListener:fn=>listener=fn};
 runtime.connectNative=host=>{
  const messages=[],disconnected=[];
  let closed=false;
  const port={onMessage:{addListener:fn=>messages.push(fn)},onDisconnect:{addListener:fn=>disconnected.push(fn)},
   disconnect(){if(closed)return;closed=true;for(const fn of disconnected)fn()},
   postMessage(message){Promise.resolve().then(()=>native(host,message)).then(reply=>{
    if(!closed)for(const fn of messages)fn(reply);
   }).catch(error=>{runtime.lastError={message:error.message};port.disconnect();runtime.lastError=undefined})}};
  return port;
 };
 chrome.action=chrome.action||{setBadgeText(){},setTitle(){}};
 const getTab=chrome.tabs?.get;
 if(getTab)chrome.tabs.get=async id=>({id,...await getTab(id)});
 const context=vm.createContext({chrome,URL,Date,Map});
 context.importScripts=(...files)=>{for(const file of files)vm.runInContext(fs.readFileSync(path.join(__dirname,'../browser_extension',file),'utf8'),context)};
 vm.runInContext(fs.readFileSync(path.join(__dirname,'../browser_extension/background.js'),'utf8'),context);
 const dispatch=(message,sender={id,url:runtime.getURL('popup.html')})=>new Promise((resolve,reject)=>{
  try{if(listener(message,sender,resolve)!==true)reject(Error('No handler accepted the message'))}catch(error){reject(error)}
 });
 runtime.sendMessage=message=>dispatch(message);
 return {dispatch};
};
