const status = document.getElementById('status');
const fillButton = document.getElementById('fill');
fillButton.addEventListener('click', async () => {
  if (fillButton.disabled) return;
  fillButton.disabled = true;
  status.textContent = 'Ожидание подтверждения в Windows…';
  try {
    const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
    const url = new URL(tab.url);
    if (url.protocol !== 'https:') throw Error('Поддерживаются только HTTPS-сайты.');
    // The native host validates the same URL and prompts the user for every request.
    const reply = await chrome.runtime.sendNativeMessage('ru.moiparoli.host', {
      action: 'get_credentials', url: tab.url
    });
    if (!reply?.ok) throw Error(reply?.error || 'Нет ответа от приложения');
    // A tab can navigate while Windows confirmation is open. Never fill a new URL.
    const latest = await chrome.tabs.get(tab.id);
    if (latest.url !== tab.url || !latest.active) throw Error('Вкладка изменилась — запрос отменён.');
    const injection = await chrome.scripting.executeScript({
      target: {tabId: tab.id}, func: (login, password, expectedOrigin) => {
        if (location.origin !== expectedOrigin || window !== window.top) return false;
        const candidates = [...document.querySelectorAll('input')].filter(el =>
          !el.disabled && !el.readOnly && el.getClientRects().length > 0);
        const has=(el,token)=>el.autocomplete.toLowerCase().split(/\s+/).includes(token);
        const pass=candidates.find(el=>has(el,'current-password'))||
          candidates.find(el=>el.type==='password'&&!has(el,'new-password'));
        const fields=pass?.form?candidates.filter(el=>el.form===pass.form):candidates;
        const eligible=fields.filter(el=>['email','text','tel'].includes(el.type)&&!has(el,'one-time-code')&&!has(el,'current-password')&&!has(el,'new-password')&&
          !/search|query|^q$|password|otp|verification.?code|auth.?code/i.test(el.name+' '+el.id));
        const user=eligible.find(el=>has(el,'username')||has(el,'email')||el.type==='email')||
          eligible.find(el=>/user|login|email|identifier|account|phone|mobile/i.test(el.name+' '+el.id))||
          (eligible.length===1?eligible[0]:null);
        if(!pass&&!user)return false;
        function setValue(el, value) {
          if (!el) return;
          const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
          setter.call(el, value);
          el.dispatchEvent(new Event('input', {bubbles: true}));
          el.dispatchEvent(new Event('change', {bubbles: true}));
        }
        setValue(user, login);
        setValue(pass, password);
        return true;
      }, args: [reply.login, reply.password, url.origin]
    });
    status.textContent = injection?.[0]?.result ? 'Поля заполнены. Проверьте сайт перед входом.' : 'Форма пароля не найдена.';
  } catch (err) { status.textContent = typeof connectionError==='function' ? connectionError(err) : (err.message || 'Ошибка заполнения'); }
  finally { fillButton.disabled = false; }
});

