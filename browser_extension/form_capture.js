(()=>{
  function capture(scope=document,remembered='') {
    const fields=[...scope.querySelectorAll('input')].filter(e=>!e.disabled&&e.getClientRects().length>0);
    const has=(e,token)=>e.autocomplete.toLowerCase().split(/\s+/).includes(token);
    const passwords=fields.filter(e=>e.type==='password'||has(e,'new-password')||has(e,'current-password'));
    const active=passwords.includes(document.activeElement)?document.activeElement:null;
    const pass=passwords.find(e=>has(e,'new-password'))||active||passwords.find(e=>has(e,'current-password'))||
      (new Set(passwords.map(e=>e.value).filter(Boolean)).size<=1?passwords.find(e=>e.value):null);
    const relevant=pass?.form?fields.filter(e=>e.form===pass.form):fields;
    const login=relevant.find(e=>has(e,'username')||has(e,'email')||e.type==='email')||
      relevant.find(e=>['text','tel'].includes(e.type)&&/user|login|email|identifier|account|phone|mobile/i.test(e.name+' '+e.id))||
      (relevant.filter(e=>e.type==='text'&&!/search/i.test(e.name+' '+e.id)).length===1?
        relevant.find(e=>e.type==='text'&&!/search/i.test(e.name+' '+e.id)):null);
    return {url:location.href,credentials:{title:location.hostname,login:login?.value||remembered,password:pass?.value||''}};
  }
  window.MoiParoliCapture=capture;
})();
