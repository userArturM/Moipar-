import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
const manifest = JSON.parse(fs.readFileSync('browser_extension/manifest.json', 'utf8'));
assert.equal(manifest.manifest_version, 3);
assert.deepEqual(manifest.permissions.sort(), ['activeTab', 'nativeMessaging', 'scripting', 'storage'].sort());
const source = fs.readFileSync('browser_extension/popup.js', 'utf8');
async function check({url='https://example.com/login', latest=url, ok=true} = {}) {
  const status = {textContent:''};
  const button = {disabled:false, addEventListener(_, handler) { this.handler=handler; }};
  const calls = [];
  const chrome = {
    tabs: {query:async()=>[{id:1,url}], get:async()=>({url:latest,active:true})},
    runtime: {sendNativeMessage:async(host, request)=>{
      calls.push(['native',host,request]);
      return ok ? {ok:true,login:'demo',password:'test-only'} : {ok:false,error:'Отменено'};
    }},
    scripting: {executeScript:async(request)=>{calls.push(['fill',request.args]);return [{result:true}];}}
  };
  vm.runInNewContext(source, {document:{getElementById:id=>id==='status'?status:button}, chrome, URL});
  await button.handler();
  assert.equal(button.disabled,false);
  return {calls,status};
}
assert.equal((await check({url:'http://example.com'})).calls.length,0);
assert.equal((await check({latest:'https://evil.example/login'})).calls.filter(x=>x[0]==='fill').length,0);
assert.equal((await check({ok:false})).calls.filter(x=>x[0]==='fill').length,0);
const success=await check();
assert.deepEqual(Array.from(success.calls.find(x=>x[0]==='fill')[1]), ['demo','test-only','https://example.com']);
assert(!success.status.textContent.includes('test-only'));
console.log('Extension checks passed: HTTPS, consent, navigation changes, scoped fill');
