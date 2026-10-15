globalThis.MoiParoliFill = (login, password, expectedOrigin) => {
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
      };
