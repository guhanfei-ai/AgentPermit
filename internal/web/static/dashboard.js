// 首页数据层与 SVG 图表，无 CDN、第三方图表库或模拟指标。
(function () {
  "use strict";
  var root = document.querySelector("[data-dashboard]");
  if (!root) return;
  var error = root.querySelector("[data-error]");
  var refresh = root.querySelector("[data-refresh]");
  var tooltip = root.querySelector("[data-chart-tooltip]");
  var dateFormat = new Intl.DateTimeFormat("zh-CN", {timeZone:"Asia/Shanghai",hour:"2-digit",minute:"2-digit",second:"2-digit",hour12:false});
  var initial;
  try { initial = JSON.parse(document.getElementById("dashboard-data").textContent); }
  catch (_) { error.textContent="统计初始化失败，请刷新页面。"; error.hidden=false; return; }
  var period=initial.period, sequence=0, controller=null, timer=null;
  function text(tag, value, className) {
    var node=document.createElement(tag); node.textContent=value;
    if (className) node.className=className;
    return node;
  }
  function number(value) { return Number(value).toLocaleString("zh-CN"); }
  function renderRanks(key, rows) {
    var list=root.querySelector('[data-rank="'+key+'"]');
    var fragment=document.createDocumentFragment();
    var maximum=rows.length ? rows[0].count : 1;
    rows.forEach(function (row,i) {
      var li=document.createElement("li"), label=document.createElement("div");
      li.appendChild(text("span", String(i+1).padStart(2,"0"), "dash-rank-no"));
      var name=text("strong",row.name); name.title=row.name;
      label.appendChild(name); label.appendChild(text("small",row.owner)); li.appendChild(label);
      li.appendChild(text("b",number(row.count)));
      var bar=document.createElement("span"); bar.className="dash-rank-bar";
      bar.style.width=(Math.max(0,row.count/maximum)*70)+"%"; bar.setAttribute("aria-hidden","true");
      li.appendChild(bar); fragment.appendChild(li);
    });
    list.replaceChildren(fragment);
    root.querySelector('[data-empty="'+key+'"]').hidden=rows.length>0;
  }
  function svgNode(tag,attrs,label) {
    var node=document.createElementNS("http://www.w3.org/2000/svg",tag);
    Object.keys(attrs).forEach(function(key){node.setAttribute(key,attrs[key]);});
    if (label!==undefined) node.textContent=label;
    return node;
  }
  function renderTrend(points) {
    var svg=root.querySelector("[data-trend]"); svg.replaceChildren(); tooltip.hidden=true;
    var viewWidth=Math.max(280,svg.getBoundingClientRect().width);
    svg.setAttribute("viewBox","0 0 "+viewWidth+" 220");
    var left=34, top=10, width=viewWidth-54, height=180;
    var peak=5;
    points.forEach(function(p){peak=Math.max(peak,p.allowed,p.denied);});
    var maximum=Math.ceil(peak/5)*5;
    for (var i=0;i<=5;i++) {
      var y=top+height-i*height/5;
      svg.appendChild(svgNode("line",{x1:left,y1:y,x2:left+width,y2:y,class:"chart-grid"}));
      svg.appendChild(svgNode("text",{x:left-10,y:y+4,"text-anchor":"end"},number(maximum*i/5)));
    }
    var step=width/Math.max(1,points.length-1);
    points.forEach(function(point,index) {
      var x=left+index*step;
      svg.appendChild(svgNode("line",{x1:x,y1:top,x2:x,y2:top+height,class:"chart-grid"}));
      // 小屏时减少文字密度，所有点仍可通过键盘与指针查看。
      var labelStep=window.innerWidth<760 ? Math.ceil(points.length/4) : Math.ceil(points.length/12);
      if (index%labelStep===0 || index===points.length-1) svg.appendChild(svgNode("text",{x:x,y:top+height+24,"text-anchor":"middle"},point.label));
    });
    ["allowed","denied"].forEach(function (key) {
      var coords=points.map(function(p,index){return (left+index*step)+","+(top+height-p[key]/maximum*height);});
      svg.appendChild(svgNode("polyline",{points:coords.join(" "),class:"chart-"+key}));
      points.forEach(function(p,index) {
        svg.appendChild(svgNode("circle",{cx:left+index*step,cy:top+height-p[key]/maximum*height,r:2.7,class:"chart-point chart-"+key}));
      });
    });
    points.forEach(function (point,index) {
      var hit=svgNode("rect",{x:Math.max(left,left+(index-.5)*step),y:top,width:index===0||index===points.length-1?step/2:step,height:height,class:"chart-focus",tabindex:0,role:"img","aria-label":point.label+" 允许 "+point.allowed+" 次，拒绝 "+point.denied+" 次"});
      var show=function(){tooltip.textContent=point.label+" · 允许 "+number(point.allowed)+" · 拒绝 "+number(point.denied); tooltip.hidden=false;};
      hit.addEventListener("pointerenter",show); hit.addEventListener("focus",show);
      hit.addEventListener("pointerleave",function(){tooltip.hidden=true;}); hit.addEventListener("blur",function(){tooltip.hidden=true;});
      svg.appendChild(hit);
    });
  }
  function render(data) {
    root.querySelectorAll("[data-stat]").forEach(function(node) {
      var key=node.dataset.stat;
      var value=key.split(".").reduce(function(obj,p){return obj[p];},data);
      if (key==="approval_rate") value=value===null?"—":value.toFixed(1)+"%";
      else if (key==="runtime.average_ms") value=value===null?"—":value.toFixed(1);
      else value=number(value);
      node.textContent=value;
    });
    root.querySelectorAll("[data-period]").forEach(function(link) {
      if (link.dataset.period===data.period) link.setAttribute("aria-current","true"); else link.removeAttribute("aria-current");
    });
    root.querySelector(".dash-scope").textContent=data.scope;
    refresh.title="更新于 "+dateFormat.format(new Date(data.generated_at));
    root.querySelector(".dash-process").title="当前进程启动于 "+new Date(data.runtime.started_at).toLocaleString("zh-CN",{timeZone:"Asia/Shanghai"})+"；实时窗口为最近5分钟";
    renderTrend(data.trend); renderRanks("capability_ranking",data.capability_ranking); renderRanks("credential_ranking",data.credential_ranking);
    var items=document.createDocumentFragment();
    data.activity.forEach(function(item) {
      var li=document.createElement("li"); if (item.outcome==="failure") li.className="failed";
      var time=text("time",dateFormat.format(new Date(item.time))); time.dateTime=item.time; time.title=new Date(item.time).toLocaleString("zh-CN",{timeZone:"Asia/Shanghai"});
      li.appendChild(time); li.appendChild(text("span",item.title)); var resource=text("span",item.resource); resource.title=item.resource; li.appendChild(resource); items.appendChild(li);
    });
    root.querySelector("[data-activity]").replaceChildren(items);
    root.querySelector("[data-activity-empty]").hidden=data.activity.length>0;
    initial=data;
  }
  function schedule() {
    clearTimeout(timer);
    if (!document.hidden) timer=setTimeout(function(){load(period);},10000);
  }
  async function load(nextPeriod) {
    clearTimeout(timer); if (controller) controller.abort();
    controller=new AbortController(); var signal=controller.signal; var current=++sequence;
    var timeout=setTimeout(function(){controller && current===sequence && controller.abort();},10000);
    refresh.disabled=true; refresh.querySelector("span").textContent="刷新中";
    try {
      var response=await fetch("/dashboard/stats?period="+encodeURIComponent(nextPeriod),{credentials:"same-origin",headers:{Accept:"application/json"},signal:signal,cache:"no-store"});
      if (response.redirected && new URL(response.url).pathname==="/login") { window.location.assign("/login"); return; }
      if (!response.ok) throw new Error("refresh failed");
      var data=await response.json(); if (current!==sequence) return;
      render(data); period=data.period; error.hidden=true;
      var url=new URL(window.location.href); url.searchParams.set("period",period); history.replaceState(null,"",url);
    } catch (_) {
      if (current===sequence && !document.hidden) { error.textContent="刷新失败，保留上次数据。可稍后重试。"; error.hidden=false; }
    } finally {
      clearTimeout(timeout);
      if (current===sequence) { refresh.disabled=false; refresh.querySelector("span").textContent="刷新"; schedule(); }
    }
  }
  root.querySelectorAll("[data-period]").forEach(function(link) {
    link.addEventListener("click",function(e){if(e.metaKey||e.ctrlKey||e.shiftKey||e.altKey)return;e.preventDefault();load(link.dataset.period);});
  });
  refresh.addEventListener("click",function(){load(period);});
  document.addEventListener("visibilitychange",function(){if(document.hidden){clearTimeout(timer);if(controller)controller.abort();}else load(period);});
  window.addEventListener("resize",function(){renderTrend(initial.trend);});
  render(initial); schedule();
})();
