// Opt-in WebAuthn provider. Requests come only from the browser's privileged API.
const bitoraPasskeys=(()=>{
  const requests=new Map();let wired=false;let enabled=false;
  function api(){return chrome.webAuthenticationProxy}
  async function respond(kind,request){
    const service=api();const token={port:null,active:true};requests.set(request.requestId,token);
    const method=kind==='create'?'completeCreateRequest':'completeGetRequest';
    try{
      const options=JSON.parse(request.requestDetailsJson);
      const origin=options.extensions?.remoteDesktopClientOverride;
      const url=new URL(origin?.origin||'about:blank');
      const secure=url.protocol==='https:'||(url.protocol==='http:'&&url.hostname==='localhost');
      if(!enabled||!origin?.sameOriginWithAncestors||!secure)throw Error('Origin unavailable');
      const reply=await new Promise((resolve,reject)=>{
        const port=token.port=chrome.runtime.connectNative('ru.moiparoli.host');let settled=false;
        port.onMessage.addListener(value=>{if(settled)return;settled=true;resolve(value);port.disconnect()});
        port.onDisconnect.addListener(()=>{if(!settled){settled=true;reject(Error('Native request canceled'))}});
        port.postMessage({action:'passkey_'+kind,options});
      });
      if(!token.active)return;
      if(!reply?.ok)await service[method]({requestId:request.requestId,error:{name:reply?.name||'NotAllowedError',message:'Bitora: request not approved'}});
      else await service[method]({requestId:request.requestId,responseJson:JSON.stringify(reply.credential)});
    }catch(error){
      if(token.active)await service[method]({requestId:request.requestId,error:{name:'NotAllowedError',message:'Bitora: request canceled or unavailable'}}).catch(()=>{});
    }finally{requests.delete(request.requestId);token.active=false;token.port?.disconnect()}
  }
  function wire(){
    const service=api();if(wired||!service)return;
    service.onCreateRequest.addListener(request=>{respond('create',request)});
    service.onGetRequest.addListener(request=>{respond('get',request)});
    service.onRequestCanceled.addListener(id=>{const token=requests.get(id);if(token){token.active=false;token.port?.disconnect();requests.delete(id)}});
    service.onIsUvpaaRequest.addListener(request=>{service.completeIsUvpaaRequest({requestId:request.requestId,isUvpaa:enabled}).catch(()=>{})});
    wired=true;
  }
  async function control(action){
    if(action==='passkeys_status'&&!api())return {ok:true,available:true,enabled:false,permissionRequired:true};
    if(!api())return {ok:false,available:false,error:'В этом браузере API ключей доступа недоступен.'};
    wire();
    if(action==='passkeys_status')return {ok:true,available:true,enabled};
    if(action==='passkeys_enable'){
      if(!await chrome.permissions.contains({permissions:['webAuthenticationProxy']}))throw Error('Разрешение браузера не получено');
      const error=await api().attach();if(error)throw Error(String(error));enabled=true;
      await chrome.storage.local.set({bitoraPasskeysEnabled:true});
    }else{
      enabled=false;
      for(const token of requests.values()){token.active=false;token.port?.disconnect()}
      requests.clear();await api().detach();await chrome.storage.local.set({bitoraPasskeysEnabled:false});
    }
    return {ok:true,available:true,enabled};
  }
  if(api()){
    wire();
    chrome.storage.local.get('bitoraPasskeysEnabled').then(value=>{
      if(value.bitoraPasskeysEnabled)return control('passkeys_enable');
    }).catch(()=>{});
  }
  return {control};
})();
