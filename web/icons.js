"use strict";
// Small, dependency-free stroke icons matching the landing page's icon language.
(() => {
  const paths = {
    overview:'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',
    runs:'M8 6h13 M8 12h13 M8 18h13 M3 6h.01 M3 12h.01 M3 18h.01',
    agents:'M12 3 3 8v8l9 5 9-5V8z M3 8l9 5 9-5 M12 13v8',
    approvals:'M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6z M8 12l3 3 5-6',
    policies:'M4 6h16 M4 12h16 M4 18h16 M8 3v6 M16 9v6 M10 15v6',
    audit:'M6 3h9l4 4v14H6z M14 3v5h5 M9 12h7 M9 16h7',
    budgets:'M3 18h18 M6 14v-4 M12 14V6 M18 14V3',
    signups:'M4 5h16v14H4z M4 7l8 6 8-6',
    providers:'M12 2v4 M12 18v4 M4.93 4.93l2.83 2.83 M16.24 16.24l2.83 2.83 M2 12h4 M18 12h4 M4.93 19.07l2.83-2.83 M16.24 7.76l2.83-2.83 M9 12a3 3 0 1 0 6 0 3 3 0 0 0-6 0',
    firewall:'M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6z M9 12h6',
    skills:'M4 4h6v6H4z M14 4h6v6h-6z M4 14h6v6H4z M14 14h6v6h-6z',
    trust:'M12 3a5 5 0 0 0 5 5c0 3-2 4-5 6-3-2-5-3-5-6a5 5 0 0 0 5-5z M8 18h8',
    coverage:'M5 4h14v16H5z M8 9h8 M8 13h5 M8 17h7',
    refresh:'M20 11a8 8 0 1 0-2.34 5.66 M20 5v6h-6',
    connect:'M8 12h8 M12 8v8 M5 4h14v16H5z',
    info:'M12 9v7 M12 6h.01 M3 12a9 9 0 1 0 18 0 9 9 0 0 0-18 0',
    empty:'M4 7h16v12H4z M8 7V4h8v3 M9 12h6',
    activity:'M3 12h4l2-6 4 12 2-6h6',
    spend:'M12 2v20 M17 6.5c0-1.4-2.2-2.5-5-2.5S7 5.1 7 7s2.2 3 5 3 5 1.1 5 3-2.2 3-5 3-5-1.1-5-2.5',
    tokens:'M12 3 3 8v8l9 5 9-5V8z M3 8l9 5 9-5',
    status:'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18 M8 12h8'
  };
  const aliases={guide:'overview',operations:'approvals',policy:'policies',employees:'agents',traces:'runs',auditability:'coverage',integrations:'connect',context:'agents',mining:'runs',workflows:'skills'};
  function makeIcon(name){
    const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');
    svg.setAttribute('viewBox','0 0 24 24');svg.setAttribute('class','icon');svg.setAttribute('aria-hidden','true');
    const path=document.createElementNS(svg.namespaceURI,'path');path.setAttribute('d',paths[aliases[name]||name]||paths.overview);svg.append(path);
    return svg;
  }
  function decorate(){
    document.querySelectorAll('[data-icon]').forEach(el=>{
      const name=el.getAttribute('data-icon')||'overview';
      const current=el.querySelector(':scope > svg');
      if(current&&current.dataset.iconName===name)return;
      if(current)current.remove();
      const svg=makeIcon(name);svg.dataset.iconName=name;el.prepend(svg);
    });
  }
  decorate();
  new MutationObserver(decorate).observe(document.body,{childList:true,subtree:true,attributes:true,attributeFilter:['data-icon']});
})();
