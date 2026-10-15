import bindWorker from './browser_test_bridge.cjs';
import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
const source=fs.readFileSync('browser_extension/save.js','utf8');
async function scenario(mode){
  const nodes={status:{textContent:''},save:{disabled:false},autosave:{disabled:false,checked:false},connect:{}};
  for(const node of Object.values(nodes))node.addEventListener=(_,fn)=>node.handler=fn;
  const messages=[],stored=[];
  const chrome={
    tabs:{query:async()=>[{id:1,url:'https://example.test/login'}],get:async()=>({active:true,url:mode==='changed'?'https://evil.test/':'https://example.test/login'})},
    storage:{local:{get:async()=>({}),set:async data=>stored.push(data)}},
    permissions:{request:async()=>false,remove:async()=>{}},
    scripting:{executeScript:async()=>[{result:{url:'https://example.test/login',credentials:{title:'Example',login:'test',password:'Fake!789'}}}]},
    runtime:{sendNativeMessage:async(host,message)=>{
      messages.push({host,...structuredClone(message)});
      return mode==='cancel'?{ok:false,error:'Canceled'}:{ok:true,message:'Пароль сохранён'};
    }}
  };
  const context={document:{getElementById:id=>nodes[id]},chrome,URL,status:nodes.status};
  bindWorker(chrome);
  vm.runInNewContext(source,context);
  await new Promise(resolve=>setTimeout(resolve,0));
  await nodes.save.handler();
  assert.equal(nodes.save.disabled,false);
  assert.equal(stored.length,0,'Passwords must not be stored in browser storage');
  return {nodes,messages};
}
const success=await scenario('success');
assert.equal(success.messages[0].action,'save_credentials');
assert.equal(success.messages[0].credentials.password,'Fake!789');
assert.equal((await scenario('changed')).messages.length,0);
assert.match((await scenario('cancel')).nodes.status.textContent,/Canceled/);
console.log('Browser save checks passed: explicit save, cancel, changed tab, no browser password storage');
async function offer(mode){
  let listener;
  const calls=[];
  const chrome={runtime:{onMessage:{addListener:fn=>listener=fn},sendNativeMessage:async(host,msg)=>{
    calls.push(structuredClone(msg));return {ok:true};}},
    storage:{local:{get:async key=>({[key]:mode!=='disabled'})}},
    permissions:{contains:async()=>mode!=='denied'},
    action:{setBadgeText:()=>{},setTitle:()=>{}}};
  vm.runInNewContext(fs.readFileSync('browser_extension/background.js','utf8'),{chrome,URL,Date,Map,importScripts:()=>{}});
  const message={action:'offer_save',url:'https://example.test/login',credentials:{login:'test',password:'Fake!789'}};
  await new Promise(resolve=>listener(message,{url:mode==='spoof'?'https://evil.test':'https://example.test/login',
                                            tab:{id:1,url:'https://example.test/login'}},resolve));
  return {calls,message};
}
assert.equal((await offer('disabled')).calls.length,0);
assert.equal((await offer('denied')).calls.length,0);
assert.equal((await offer('spoof')).calls.length,0);
const offered=await offer('enabled');
assert.equal(offered.calls.length,1);
assert.equal(offered.message.credentials.password,'');
console.log('Save offers require matching site, opt-in and browser permission');
let twoStepListener;
const twoStepCalls=[];
const twoStepChrome={runtime:{onMessage:{addListener:fn=>twoStepListener=fn},sendNativeMessage:async(host,message)=>{twoStepCalls.push(structuredClone(message));return {ok:true}}},
  storage:{local:{get:async key=>({[key]:true})}},permissions:{contains:async()=>true},action:{setBadgeText:()=>{},setTitle:()=>{}}};
vm.runInNewContext(fs.readFileSync('browser_extension/background.js','utf8'),{chrome:twoStepChrome,URL,Date,Map,importScripts:()=>{}});
const twoStepSender={url:'https://example.test/password',tab:{id:2,url:'https://example.test/password'}};
const sendTwoStep=message=>new Promise(resolve=>twoStepListener(message,twoStepSender,resolve));
await sendTwoStep({action:'remember_login',url:'https://example.test/username',login:'two-step@example.test'});
await sendTwoStep({action:'offer_save',url:'https://example.test/password',credentials:{login:'',password:'FakeStep2!789'}});
await sendTwoStep({action:'offer_save',url:'https://example.test/password',credentials:{login:'',password:'FakeStep2!789'}});
assert.equal(twoStepCalls.length,1,'Click and submit must not open duplicate native dialogs');
assert.equal(twoStepCalls[0].credentials.login,'two-step@example.test');
console.log('Two-step username stays within the tab/site; duplicate offers are suppressed');
