const assert=require('node:assert/strict');
const bindWorker=require('./browser_test_bridge.cjs');
function fixture(native){
 const calls=[];
 const chrome={runtime:{sendNativeMessage:async(host,message)=>{calls.push(structuredClone(message));return native(message)}},
  action:{setBadgeText:options=>calls.push({action:'badge',...options}),setTitle:options=>calls.push({action:'title',...options})},
  tabs:{get:async id=>({id,url:'https://example.test/login',active:true})},
  scripting:{executeScript:async request=>{calls.push({action:'injected',args:[...request.args]});return [{result:true}]}}};
 return {chrome,calls,...bindWorker(chrome)};
}
(async()=>{
 let release;
 const native=new Promise(resolve=>release=resolve);
 const f=fixture(()=>native);
 const message={action:'manual_fill',tabId:1,url:'https://example.test/login'};
 const operation=f.dispatch(message);
 await new Promise(r=>setImmediate(r));
 // The popup can disappear; the worker still owns the native port and fill.
 const secret={ok:true,login:'synthetic',password:'SyntheticOnly!789'};
 release(secret);
 const response=await operation;
 assert(response.ok);
 assert(!('password' in response));
 assert.equal(f.calls.find(c=>c.action==='injected').args[1],'SyntheticOnly!789');
 assert.equal(secret.password,'');
 const spoof=fixture(()=>{throw Error('must not contact native host')});
 assert.equal((await spoof.dispatch(message,{id:'untrusted',url:'https://example.test',tab:{id:1}})).ok,false);
 assert.equal(spoof.calls.length,0);
 const disconnected=fixture(()=>{throw Error('Native host disconnected')});
 assert.equal((await disconnected.dispatch({...message})).ok,false);
 assert(disconnected.calls.some(c=>c.action==='badge'&&c.text==='!'));
 const absent=fixture(()=>({ok:true,login:'synthetic',password:'SyntheticOnly!789'}));
 absent.chrome.scripting.executeScript=async()=>[{result:false}];
 const notFilled=await absent.dispatch({...message});
 assert.equal(notFilled.ok,false);
 assert.equal(notFilled.error,'Форма пароля не найдена.');
 assert(absent.calls.some(c=>c.action==='badge'&&c.text==='!'));
 let navigate;
 const slow=fixture(()=>new Promise(resolve=>navigate=resolve));
 const delayed=slow.dispatch(message);
 await new Promise(r=>setImmediate(r));
 slow.chrome.tabs.get=async id=>({id,url:'https://other.test',active:true});
 navigate({ok:true,login:'synthetic',password:'SyntheticOnly!789'});
 assert.equal((await delayed).ok,false);
 assert(!slow.calls.some(c=>c.action==='injected'));
 let finish;
 const duplicate=fixture(()=>new Promise(resolve=>finish=resolve));
 const first=duplicate.dispatch(message);await new Promise(r=>setImmediate(r));
 assert.equal((await duplicate.dispatch(message)).ok,false);
 finish({ok:false,error:'Cancelled'});await first;
 console.log('Worker checks passed: popup lifetime, native approval, secret disposal, spoof protection, navigation and duplicate requests.');
})().catch(error=>{console.error(error);process.exitCode=1});
