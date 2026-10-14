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
        const pass = candidates.find(el => el.type === 'password');
        if (!pass) return false;
        const user = candidates.find(el => ['email', 'text'].includes(el.type) &&
          (el.autocomplete === 'username' || /user|login|email/i.test(el.name || el.id || '')))
          || candidates.find(el => ['email', 'text'].includes(el.type));
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
  } catch (err) { status.textContent = err.message || 'Ошибка заполнения'; }
  finally { fillButton.disabled = false; }
});
