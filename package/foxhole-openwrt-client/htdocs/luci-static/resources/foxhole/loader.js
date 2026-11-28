'use strict';
'require baseclass';

return baseclass.extend({
  mount: function(label) {
    if (!document.getElementById('foxhole-pixel-loader-style')) {
      document.head.appendChild(E('link',{id:'foxhole-pixel-loader-style',rel:'stylesheet',
        href:L.resource('foxhole/pixel-loader.css')+'?v=1.0.20-r1-ui23'}));
    }
    const pending=document.querySelector('#view > .spinning');
    if (pending) {
      pending.classList.replace('spinning','foxhole-loading');
      pending.setAttribute('role','status');
      if (label) pending.textContent = label;
    }
  }
});
