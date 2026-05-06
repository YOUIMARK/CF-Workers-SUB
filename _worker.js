// CF-Workers-SUB — 汇聚订阅 Worker
// ---- 默认配置（模块级常量，不在请求中修改） ----
const DEFAULT_TOKEN = 'auto';
const DEFAULT_FILENAME = 'CF-Workers-SUB';
const DEFAULT_SUB_UPDATE_HOURS = 6;
const SUB_FETCH_TIMEOUT_MS = 8000;
const MAIN_DATA_DEFAULT = `
https://cfxr.eu.org/getSub
`;

let defaultGuestToken = '';                       // 模块级默认值，仅在 env 未提供时使用
let defaultUrls = [];

// ---- 工具函数 ----

/** HTML 实体转义，防止 XSS */
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** 将多行文本清洗并按换行拆分为数组 */
async function splitLines(text) {
  let cleaned = text.replace(/[	"'|\r\n]+/g, '\n').replace(/\n+/g, '\n');
  if (cleaned.charAt(0) === '\n') cleaned = cleaned.slice(1);
  if (cleaned.charAt(cleaned.length - 1) === '\n') cleaned = cleaned.slice(0, cleaned.length - 1);
  return cleaned.split('\n');
}

async function getNginxPage() {
  return `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
  body { width: 35em; margin: 0 auto; font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p>
<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>
<p><em>Thank you for using nginx.</em></p>
</body>
</html>`;
}

function base64Decode(str) {
  const bytes = new Uint8Array(atob(str).split('').map(c => c.charCodeAt(0)));
  return new TextDecoder('utf-8').decode(bytes);
}

async function md5md5(text) {
  const encoder = new TextEncoder();
  const firstPass = await crypto.subtle.digest('MD5', encoder.encode(text));
  const firstHex = Array.from(new Uint8Array(firstPass))
    .map(b => b.toString(16).padStart(2, '0')).join('');
  const secondPass = await crypto.subtle.digest('MD5', encoder.encode(firstHex.slice(7, 27)));
  const secondHex = Array.from(new Uint8Array(secondPass))
    .map(b => b.toString(16).padStart(2, '0')).join('');
  return secondHex.toLowerCase();
}

function isValidBase64(str) {
  const clean = str.replace(/\s/g, '');
  // 长度必须是 4 的倍数
  if (clean.length % 4 !== 0) return false;
  // 只允许 base64 字符集，末尾最多两个 '='
  if (!/^[A-Za-z0-9+/]+=*$/.test(clean)) return false;
  const paddingLen = (clean.match(/=+$/) || [''])[0].length;
  if (paddingLen > 2) return false;
  return true;
}

function clashFix(content) {
  if (content.includes('wireguard') && !content.includes('remote-dns-resolve')) {
    const lines = content.includes('\r\n') ? content.split('\r\n') : content.split('\n');
    let result = '';
    for (const line of lines) {
      if (line.includes('type: wireguard')) {
        result += line.replace(/, mtu: 1280, udp: true/g, ', mtu: 1280, remote-dns-resolve: true, udp: true') + '\n';
      } else {
        result += line + '\n';
      }
    }
    return result;
  }
  return content;
}

function encodeBase64Fallback(data) {
  const binary = new TextEncoder().encode(data);
  let base64 = '';
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  for (let i = 0; i < binary.length; i += 3) {
    const b1 = binary[i], b2 = binary[i + 1] || 0, b3 = binary[i + 2] || 0;
    base64 += chars[b1 >> 2];
    base64 += chars[((b1 & 3) << 4) | (b2 >> 4)];
    base64 += chars[((b2 & 15) << 2) | (b3 >> 6)];
    base64 += chars[b3 & 63];
  }
  const remainder = binary.length % 3;
  const padding = remainder === 0 ? 0 : 3 - remainder;
  return base64.slice(0, base64.length - padding) + '=='.slice(0, padding);
}

// ---- SSRF 防护 ----

const BLOCKED_HOSTS = [
  '127.0.0.1', 'localhost', '0.0.0.0', '[::1]', '::1',
  '169.254.169.254',                       // AWS / 云元数据
  'metadata.google.internal',              // GCP 元数据
];

const BLOCKED_IP_PATTERNS = [
  /^10\.\d+\.\d+\.\d+$/,
  /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/,
  /^192\.168\.\d+\.\d+$/,
  /^127\.\d+\.\d+\.\d+$/,
  /^0\.0\.0\.0$/,
];

function isInternalHost(hostname) {
  const lower = hostname.toLowerCase();
  if (BLOCKED_HOSTS.includes(lower)) return true;
  for (const pattern of BLOCKED_IP_PATTERNS) {
    if (pattern.test(lower)) return true;
  }
  return false;
}

// ---- 网络请求函数 ----

async function sendMessage(type, ip, botToken, chatId, add_data = '') {
  if (!botToken || !chatId) return;
  let msg = '';
  try {
    const resp = await fetch(`https://ip-api.com/json/${encodeURIComponent(ip)}?lang=zh-CN`);
    if (resp.ok) {
      const info = await resp.json();
      msg = `${type}\nIP: ${escapeHtml(ip)}\n国家: ${escapeHtml(info.country)}\n<tg-spoiler>城市: ${escapeHtml(info.city)}\n组织: ${escapeHtml(info.org)}\nASN: ${escapeHtml(info.as)}\n${add_data}`;
    } else {
      msg = `${type}\nIP: ${escapeHtml(ip)}\n<tg-spoiler>${add_data}`;
    }
  } catch {
    msg = `${type}\nIP: ${escapeHtml(ip)}\n<tg-spoiler>${add_data}`;
  }
  const url = `https://api.telegram.org/bot${encodeURIComponent(botToken)}/sendMessage?chat_id=${encodeURIComponent(chatId)}&parse_mode=HTML&text=${encodeURIComponent(msg)}`;
  return fetch(url, {
    method: 'GET',
    headers: {
      'Accept': 'text/html,application/xhtml+xml,application/xml;',
      'Accept-Encoding': 'gzip, deflate, br',
      'User-Agent': 'Mozilla/5.0 Chrome/90.0.4430.72'
    }
  });
}

async function proxyURL(proxyUrlList, url) {
  const URLs = await splitLines(proxyUrlList);
  const fullURL = URLs[Math.floor(Math.random() * URLs.length)];
  const parsedURL = new URL(fullURL);

  // SSRF 防护：禁止代理到内网地址
  if (isInternalHost(parsedURL.hostname)) {
    return new Response('Forbidden', { status: 403 });
  }

  let URLProtocol = parsedURL.protocol.slice(0, -1) || 'https';
  let URLHostname = parsedURL.hostname;
  let URLPathname = parsedURL.pathname;
  const URLSearch = parsedURL.search;

  if (URLPathname.charAt(URLPathname.length - 1) === '/') {
    URLPathname = URLPathname.slice(0, -1);
  }
  URLPathname += url.pathname;

  const newURL = `${URLProtocol}://${URLHostname}${URLPathname}${URLSearch}`;
  const response = await fetch(newURL);
  const newResponse = new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers
  });
  newResponse.headers.set('X-New-URL', newURL);
  return newResponse;
}

async function getUrl(request, targetUrl, appendUA, userAgentHeader, signal) {
  const newHeaders = new Headers(request.headers);
  newHeaders.set('User-Agent', `${atob('djJyYXlOLzYuNDU=')} cmliu/CF-Workers-SUB ${appendUA}(${userAgentHeader})`);

  const modifiedRequest = new Request(targetUrl, {
    method: request.method,
    headers: newHeaders,
    body: request.method === 'GET' ? null : request.body,
    redirect: 'follow',
  });

  console.log(`请求URL: ${targetUrl}`);
  console.log(`请求方法: ${request.method}`);

  return fetch(modifiedRequest, { signal });
}

async function getSub(api, request, appendUA, userAgentHeader) {
  if (!api || api.length === 0) return [[], ''];

  const uniqueApi = [...new Set(api)];
  let newapi = '';
  let subConverterUrls = '';
  let abnormalSubs = '';

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), SUB_FETCH_TIMEOUT_MS);

  try {
    const responses = await Promise.allSettled(
      uniqueApi.map(apiUrl =>
        getUrl(request, apiUrl, appendUA, userAgentHeader, controller.signal)
          .then(response => response.ok ? response.text() : Promise.reject(response))
      )
    );

    const modifiedResponses = responses.map((response, index) => {
      if (response.status === 'rejected') {
        const reason = response.reason;
        if (reason && reason.name === 'AbortError') {
          return { status: '超时', value: null, apiUrl: uniqueApi[index] };
        }
        console.error(`请求失败: ${uniqueApi[index]}, 错误: ${reason?.status} ${reason?.statusText}`);
        return { status: '请求失败', value: null, apiUrl: uniqueApi[index] };
      }
      return { status: response.status, value: response.value, apiUrl: uniqueApi[index] };
    });

    for (const response of modifiedResponses) {
      if (response.status !== 'fulfilled') continue;
      const content = response.value || '';
      if (content.includes('proxies:')) {
        subConverterUrls += '|' + response.apiUrl;
      } else if (content.includes('outbounds"') && content.includes('inbounds"')) {
        subConverterUrls += '|' + response.apiUrl;
      } else if (content.includes('://')) {
        newapi += content + '\n';
      } else if (isValidBase64(content)) {
        newapi += base64Decode(content) + '\n';
      } else {
        const host = (response.apiUrl.split('://')[1] || response.apiUrl).split('/')[0];
        abnormalSubs += `trojan://CMLiussss@127.0.0.1:8888?security=tls&allowInsecure=1&type=tcp&headerType=none#${encodeURIComponent('异常订阅 ' + host)}\n`;
      }
    }
  } catch (error) {
    console.error(error);
  } finally {
    clearTimeout(timeout);
  }

  const subContent = await splitLines(newapi + abnormalSubs);
  return [subContent, subConverterUrls];
}

async function migrateAddressList(env, txt = 'ADD.txt') {
  const oldData = await env.KV.get(`/${txt}`);
  const newData = await env.KV.get(txt);
  if (oldData && !newData) {
    await env.KV.put(txt, oldData);
    await env.KV.delete(`/${txt}`);
    return true;
  }
  return false;
}

// ---- KV 编辑页面渲染 ----

async function renderKVPage(request, env, txt, guest, config) {
  const url = new URL(request.url);
  const { fileName, token, subConverter, subConfig, subProtocol } = config;

  try {
    // POST 保存
    if (request.method === 'POST') {
      if (!env.KV) return new Response('未绑定KV空间', { status: 400 });
      try {
        const content = await request.text();
        await env.KV.put(txt, content);
        return new Response('保存成功');
      } catch (error) {
        console.error('保存KV时发生错误:', error);
        return new Response('保存失败: ' + error.message, { status: 500 });
      }
    }

    // GET 页面
    let content = '';
    const hasKV = !!env.KV;
    if (hasKV) {
      try {
        content = await env.KV.get(txt) || '';
      } catch (error) {
        console.error('读取KV时发生错误:', error);
        content = '读取数据时发生错误: ' + error.message;
      }
    }

    // 安全转义所有用户可控变量
    const safeHostname = escapeHtml(url.hostname);
    const safeToken = escapeHtml(token);
    const safeGuest = escapeHtml(guest);
    const safeFileName = escapeHtml(fileName);
    const safeSubConverter = escapeHtml(`${subProtocol}://${subConverter}`);
    const safeSubConfig = escapeHtml(subConfig);
    const safeUA = escapeHtml(request.headers.get('User-Agent') || '');

    const placeholder = 'LINK示例（一行一个节点链接即可，多行多个链接）：\n' +
      'vless://246aa795-0637-4f4c-8f64-2c8fb24c1bad@127.0.0.1:1234?encryption=none&security=tls&sni=TG.CMLiussss.loseyourip.com&allowInsecure=1&type=ws&host=TG.CMLiussss.loseyourip.com&path=%2F%3Fed%3D2560#CFnat\n' +
      'trojan://aa6ddd2f-d1cf-4a52-ba1b-2640c41a7856@218.190.230.207:41288?security=tls&sni=hk12.bilibili.com&allowInsecure=1&type=tcp&headerType=none#HK\n' +
      'ss://Y2hoY2hhMjAtdWV0Zi1wb2x5MTMwNToyRXRQcW42SFlqVU5jSG9oTGZVcEZRd25makNDUTVtaDFtSmRFTUNCdWN1V1o5UDF1ZGtSS0huVnh1bzU1azFLWHoyRm82anJndDE4VzY2b3B0eTFmNGJtMWp6ZkNmQmI%3D@84.19.31.63:50841#DE\n\n' +
      '订阅链接示例（一行一个订阅链接）：\n' +
      'https://sub.xf.free.hr/auto';

    const footerHtml = 'telegram 交流群 技术支援|实时反馈!<br>\n' +
      '<a href=\'https://t.me/CMLiussss\'>https://t.me/CMLiussss</a><br>\n' +
      '--------------------------------------------------------------<br>\n' +
      'github 项目地址 Star!Star!Star!!!<br>\n' +
      '<a href=\'https://github.com/cmliu/CF-Workers-SUB\'>https://github.com/cmliu/CF-Workers-SUB</a><br>\n' +
      '--------------------------------------------------------------<br>\n' +
      '################################################################';

    const html = `<!DOCTYPE html>
<html>
<head>
<title>${safeFileName} 订阅编辑</title>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body { margin: 0; padding: 15px; box-sizing: border-box; font-size: 13px; }
  .editor-container { width: 100%; max-width: 100%; margin: 0 auto; }
  .editor { width: 100%; height: 300px; margin: 15px 0; padding: 10px; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; font-size: 13px; line-height: 1.5; overflow-y: auto; resize: none; }
  .save-container { margin-top: 8px; display: flex; align-items: center; gap: 10px; }
  .save-btn, .back-btn { padding: 6px 15px; color: white; border: none; border-radius: 4px; cursor: pointer; }
  .save-btn { background: #4CAF50; }
  .save-btn:hover { background: #45a049; }
  .back-btn { background: #666; }
  .back-btn:hover { background: #555; }
  .save-status { color: #666; }
</style>
<script src="https://cdn.jsdelivr.net/npm/@keeex/qrcodejs-kx@1.0.2/qrcode.min.js"></script>
</head>
<body>
################################################################<br>
Subscribe / sub 订阅地址, 点击链接自动 <strong>复制订阅链接</strong> 并 <strong>生成订阅二维码</strong> <br>
---------------------------------------------------------------<br>
自适应订阅地址:<br>
<a href="javascript:void(0)" onclick="copyToClipboard('https://${safeHostname}/${safeToken}?sub','qrcode_0')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${safeHostname}/${safeToken}</a><br>
<div id="qrcode_0" style="margin: 10px 10px 10px 10px;"></div>
Base64订阅地址:<br>
<a href="javascript:void(0)" onclick="copyToClipboard('https://${safeHostname}/${safeToken}?b64','qrcode_1')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${safeHostname}/${safeToken}?b64</a><br>
<div id="qrcode_1" style="margin: 10px 10px 10px 10px;"></div>
clash订阅地址:<br>
<a href="javascript:void(0)" onclick="copyToClipboard('https://${safeHostname}/${safeToken}?clash','qrcode_2')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${safeHostname}/${safeToken}?clash</a><br>
<div id="qrcode_2" style="margin: 10px 10px 10px 10px;"></div>
singbox订阅地址:<br>
<a href="javascript:void(0)" onclick="copyToClipboard('https://${safeHostname}/${safeToken}?sb','qrcode_3')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${safeHostname}/${safeToken}?sb</a><br>
<div id="qrcode_3" style="margin: 10px 10px 10px 10px;"></div>
surge订阅地址:<br>
<a href="javascript:void(0)" onclick="copyToClipboard('https://${safeHostname}/${safeToken}?surge','qrcode_4')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${safeHostname}/${safeToken}?surge</a><br>
<div id="qrcode_4" style="margin: 10px 10px 10px 10px;"></div>
loon订阅地址:<br>
<a href="javascript:void(0)" onclick="copyToClipboard('https://${safeHostname}/${safeToken}?loon','qrcode_5')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${safeHostname}/${safeToken}?loon</a><br>
<div id="qrcode_5" style="margin: 10px 10px 10px 10px;"></div>
&nbsp;&nbsp;<strong><a href="javascript:void(0);" id="noticeToggle" onclick="toggleNotice()">查看访客订阅∨</a></strong><br>
<div id="noticeContent" class="notice-content" style="display: none;">
---------------------------------------------------------------<br>
访客订阅只能使用订阅功能，无法查看配置页！<br>
GUEST（访客订阅TOKEN）: <strong>${safeGuest}</strong><br>
---------------------------------------------------------------<br>
自适应订阅地址:<br>
<a href="javascript:void(0)" onclick="copyToClipboard('https://${safeHostname}/sub?token=${safeGuest}','guest_0')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${safeHostname}/sub?token=${safeGuest}</a><br>
<div id="guest_0" style="margin: 10px 10px 10px 10px;"></div>
Base64订阅地址:<br>
<a href="javascript:void(0)" onclick="copyToClipboard('https://${safeHostname}/sub?token=${safeGuest}&b64','guest_1')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${safeHostname}/sub?token=${safeGuest}&b64</a><br>
<div id="guest_1" style="margin: 10px 10px 10px 10px;"></div>
clash订阅地址:<br>
<a href="javascript:void(0)" onclick="copyToClipboard('https://${safeHostname}/sub?token=${safeGuest}&clash','guest_2')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${safeHostname}/sub?token=${safeGuest}&clash</a><br>
<div id="guest_2" style="margin: 10px 10px 10px 10px;"></div>
singbox订阅地址:<br>
<a href="javascript:void(0)" onclick="copyToClipboard('https://${safeHostname}/sub?token=${safeGuest}&sb','guest_3')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${safeHostname}/sub?token=${safeGuest}&sb</a><br>
<div id="guest_3" style="margin: 10px 10px 10px 10px;"></div>
surge订阅地址:<br>
<a href="javascript:void(0)" onclick="copyToClipboard('https://${safeHostname}/sub?token=${safeGuest}&surge','guest_4')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${safeHostname}/sub?token=${safeGuest}&surge</a><br>
<div id="guest_4" style="margin: 10px 10px 10px 10px;"></div>
loon订阅地址:<br>
<a href="javascript:void(0)" onclick="copyToClipboard('https://${safeHostname}/sub?token=${safeGuest}&loon','guest_5')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${safeHostname}/sub?token=${safeGuest}&loon</a><br>
<div id="guest_5" style="margin: 10px 10px 10px 10px;"></div>
</div>
---------------------------------------------------------------<br>
################################################################<br>
订阅转换配置<br>
---------------------------------------------------------------<br>
SUBAPI（订阅转换后端）: <strong>${safeSubConverter}</strong><br>
SUBCONFIG（订阅转换配置文件）: <strong>${safeSubConfig}</strong><br>
---------------------------------------------------------------<br>
################################################################<br>
${safeFileName} 汇聚订阅编辑:
<div class="editor-container">
${hasKV ? `
<textarea class="editor"
  placeholder="${escapeHtml(placeholder)}"
  id="content">${escapeHtml(content)}</textarea>
<div class="save-container">
  <button class="save-btn" onclick="saveContent(this)">保存</button>
  <span class="save-status" id="saveStatus"></span>
</div>
` : '<p>请绑定 <strong>变量名称</strong> 为 <strong>KV</strong> 的KV命名空间</p>'}
</div>
<br>
################################################################<br>
${footerHtml}
<br><br>UA: <strong>${safeUA}</strong>
<script>
function copyToClipboard(text, qrcode) {
  navigator.clipboard.writeText(text).then(() => {
    alert('已复制到剪贴板');
  }).catch(err => {
    console.error('复制失败:', err);
  });
  const qrcodeDiv = document.getElementById(qrcode);
  qrcodeDiv.innerHTML = '';
  new QRCode(qrcodeDiv, {
    text: text,
    width: 220,
    height: 220,
    colorDark: "#000000",
    colorLight: "#ffffff",
    correctLevel: QRCode.CorrectLevel.Q,
    scale: 1
  });
}

if (document.querySelector('.editor')) {
  let timer;
  const textarea = document.getElementById('content');
  const originalContent = textarea.value;

  function goBack() {
    const currentUrl = window.location.href;
    const parentUrl = currentUrl.substring(0, currentUrl.lastIndexOf('/'));
    window.location.href = parentUrl;
  }

  function replaceFullwidthColon() {
    const text = textarea.value;
    textarea.value = text.replace(/：/g, ':');
  }

  function saveContent(button) {
    try {
      const updateButtonText = (step) => { button.textContent = \`保存中: \${step}\`; };
      const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent);
      if (!isIOS) { replaceFullwidthColon(); }
      updateButtonText('开始保存');
      button.disabled = true;

      const textarea = document.getElementById('content');
      if (!textarea) { throw new Error('找不到文本编辑区域'); }

      updateButtonText('获取内容');
      let newContent, originalContent;
      try {
        newContent = textarea.value || '';
        originalContent = textarea.defaultValue || '';
      } catch (e) {
        console.error('获取内容错误:', e);
        throw new Error('无法获取编辑内容');
      }

      updateButtonText('准备状态更新函数');
      const updateStatus = (message, isError = false) => {
        const statusElem = document.getElementById('saveStatus');
        if (statusElem) {
          statusElem.textContent = message;
          statusElem.style.color = isError ? 'red' : '#666';
        }
      };

      const resetButton = () => {
        button.textContent = '保存';
        button.disabled = false;
      };

      if (newContent !== originalContent) {
        updateButtonText('发送保存请求');
        fetch(window.location.href, {
          method: 'POST',
          body: newContent,
          headers: { 'Content-Type': 'text/plain;charset=UTF-8' },
          cache: 'no-cache'
        })
        .then(response => {
          if (!response.ok) throw new Error(\`HTTP error! status: \${response.status}\`);
          const now = new Date().toLocaleString();
          document.title = \`编辑已保存 \${now}\`;
          updateStatus(\`已保存 \${now}\`);
        })
        .catch(error => {
          console.error('Save error:', error);
          updateStatus(\`保存失败: \${error.message}\`, true);
        })
        .finally(() => resetButton());
      } else {
        updateStatus('内容未变化');
        resetButton();
      }
    } catch (error) {
      console.error('保存过程出错:', error);
      button.textContent = '保存';
      button.disabled = false;
      const statusElem = document.getElementById('saveStatus');
      if (statusElem) {
        statusElem.textContent = \`错误: \${error.message}\`;
        statusElem.style.color = 'red';
      }
    }
  }

  textarea.addEventListener('blur', saveContent);
  textarea.addEventListener('input', () => {
    clearTimeout(timer);
    timer = setTimeout(saveContent, 5000);
  });
}

function toggleNotice() {
  const noticeContent = document.getElementById('noticeContent');
  const noticeToggle = document.getElementById('noticeToggle');
  if (noticeContent.style.display === 'none' || noticeContent.style.display === '') {
    noticeContent.style.display = 'block';
    noticeToggle.textContent = '隐藏访客订阅∧';
  } else {
    noticeContent.style.display = 'none';
    noticeToggle.textContent = '查看访客订阅∨';
  }
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('noticeContent').style.display = 'none';
});
</script>
</body>
</html>`;

    return new Response(html, { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
  } catch (error) {
    console.error('处理请求时发生错误:', error);
    return new Response('服务器错误: ' + error.message, {
      status: 500,
      headers: { 'Content-Type': 'text/plain;charset=utf-8' }
    });
  }
}

// ============================================================
// 主入口 — 请求处理
// ============================================================

export default {
  async fetch(request, env) {
    // ---- 1. 读取请求信息 ----
    const userAgentHeader = request.headers.get('User-Agent');
    const userAgent = userAgentHeader ? userAgentHeader.toLowerCase() : 'null';
    const url = new URL(request.url);
    const tokenParam = url.searchParams.get('token');

    // ---- 2. 构建本次请求的有效配置（局部变量，不污染模块级全局） ----
    const effectiveToken = env.TOKEN || DEFAULT_TOKEN;
    const effectiveBotToken = env.TGTOKEN || '';
    const effectiveChatId = env.TGID || '';
    const effectiveTG = env.TG || 0;
    const effectiveFileName = env.SUBNAME || DEFAULT_FILENAME;

    // 订阅转换后端
    let effectiveSubConverter = env.SUBAPI || 'SUBAPI.cmliussss.net';
    let effectiveSubProtocol = 'https';
    if (effectiveSubConverter.includes('http://')) {
      effectiveSubConverter = effectiveSubConverter.split('//')[1];
      effectiveSubProtocol = 'http';
    } else {
      effectiveSubConverter = effectiveSubConverter.split('//')[1] || effectiveSubConverter;
    }
    const effectiveSubConfig = env.SUBCONFIG || 'https://raw.githubusercontent.com/cmliu/ACL4SSR/main/Clash/config/ACL4SSR_Online_MultiCountry.ini';

    // 访客 token
    let effectiveGuestToken = env.GUESTTOKEN || env.GUEST || defaultGuestToken;
    if (!effectiveGuestToken) effectiveGuestToken = await md5md5(effectiveToken);

    // 流量 / 过期计算
    const effectiveSubUpdateTime = env.SUBUPTIME || DEFAULT_SUB_UPDATE_HOURS;

    // ---- 3. Token 生成与校验 ----
    const currentDate = new Date();
    currentDate.setHours(0, 0, 0, 0);
    const timeTemp = Math.ceil(currentDate.getTime() / 1000);
    const fakeToken = await md5md5(`${effectiveToken}${timeTemp}`);

    const pathname = url.pathname;
    const validPath = pathname === `/${effectiveToken}`
      || pathname.startsWith(`/${effectiveToken}?`)
      || pathname.startsWith(`/${effectiveToken}/`);
    const validToken = [effectiveToken, fakeToken, effectiveGuestToken].includes(tokenParam);

    // ---- 4. 鉴权分支：无效请求 ----
    if (!(validToken || validPath)) {
      if (effectiveTG == 1 && pathname !== '/' && pathname !== '/favicon.ico') {
        await sendMessage(
          `#异常访问 ${effectiveFileName}`,
          request.headers.get('CF-Connecting-IP'),
          effectiveBotToken,
          effectiveChatId,
          `UA: ${escapeHtml(userAgent)}</tg-spoiler>\n域名: ${escapeHtml(url.hostname)}\n<tg-spoiler>入口: ${escapeHtml(pathname + url.search)}</tg-spoiler>`
        );
      }
      if (env.URL302) return Response.redirect(env.URL302, 302);
      else if (env.URL) return await proxyURL(env.URL, url);
      else return new Response(await getNginxPage(), {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=UTF-8' },
      });
    }

    // ---- 5. 鉴权通过：数据源加载 ----
    let mainData = MAIN_DATA_DEFAULT;
    let subUrls = [...defaultUrls];

    if (env.KV) {
      await migrateAddressList(env, 'LINK.txt');
      if (userAgent.includes('mozilla') && !url.search) {
        await sendMessage(
          `#编辑订阅 ${effectiveFileName}`,
          request.headers.get('CF-Connecting-IP'),
          effectiveBotToken,
          effectiveChatId,
          `UA: ${escapeHtml(userAgentHeader)}</tg-spoiler>\n域名: ${escapeHtml(url.hostname)}\n<tg-spoiler>入口: ${escapeHtml(pathname + url.search)}</tg-spoiler>`
        );
        const config = {
          fileName: effectiveFileName,
          token: effectiveToken,
          subConverter: effectiveSubConverter,
          subConfig: effectiveSubConfig,
          subProtocol: effectiveSubProtocol,
        };
        return await renderKVPage(request, env, 'LINK.txt', effectiveGuestToken, config);
      } else {
        mainData = await env.KV.get('LINK.txt') || MAIN_DATA_DEFAULT;
      }
    } else {
      mainData = env.LINK || MAIN_DATA_DEFAULT;
      if (env.LINKSUB) subUrls = await splitLines(env.LINKSUB);
    }

    // 合并 & 分类链接
    const allLinks = await splitLines(mainData + '\n' + subUrls.join('\n'));
    let selfBuiltNodes = '';
    let subLinks = '';
    for (const x of allLinks) {
      if (x.toLowerCase().startsWith('http')) {
        subLinks += x + '\n';
      } else {
        selfBuiltNodes += x + '\n';
      }
    }
    mainData = selfBuiltNodes;
    subUrls = await splitLines(subLinks);

    await sendMessage(
      `#获取订阅 ${effectiveFileName}`,
      request.headers.get('CF-Connecting-IP'),
      effectiveBotToken,
      effectiveChatId,
      `UA: ${escapeHtml(userAgentHeader)}</tg-spoiler>\n域名: ${escapeHtml(url.hostname)}\n<tg-spoiler>入口: ${escapeHtml(pathname + url.search)}</tg-spoiler>`
    );

    // ---- 6. 订阅格式检测 ----
    const isSubConverterRequest = request.headers.get('subconverter-request')
      || request.headers.get('subconverter-version')
      || userAgent.includes('subconverter');

    let subFormat = 'base64';
    if (!(userAgent.includes('null') || isSubConverterRequest
      || userAgent.includes('nekobox')
      || userAgent.includes('cf-workers-sub'))) {
      if (userAgent.includes('sing-box') || userAgent.includes('singbox')
        || url.searchParams.has('sb') || url.searchParams.has('singbox')) {
        subFormat = 'singbox';
      } else if (userAgent.includes('surge') || url.searchParams.has('surge')) {
        subFormat = 'surge';
      } else if (userAgent.includes('quantumult') || url.searchParams.has('quanx')) {
        subFormat = 'quanx';
      } else if (userAgent.includes('loon') || url.searchParams.has('loon')) {
        subFormat = 'loon';
      } else if (userAgent.includes('clash') || userAgent.includes('meta')
        || userAgent.includes('mihomo') || url.searchParams.has('clash')) {
        subFormat = 'clash';
      }
    }

    let subConverterUrl;
    let subConverterURL = `${url.origin}/${await md5md5(fakeToken)}?token=${fakeToken}`;
    let reqData = mainData;

    // 追加 UA 标记
    let appendUA = 'v2rayn';
    if (url.searchParams.has('b64') || url.searchParams.has('base64')) subFormat = 'base64';
    else if (url.searchParams.has('clash')) appendUA = 'clash';
    else if (url.searchParams.has('singbox')) appendUA = 'singbox';
    else if (url.searchParams.has('surge')) appendUA = 'surge';
    else if (url.searchParams.has('quanx')) appendUA = 'Quantumult%20X';
    else if (url.searchParams.has('loon')) appendUA = 'Loon';

    // ---- 7. 拉取上游订阅 ----
    const uniqueSubUrls = [...new Set(subUrls)].filter(item => item.trim());
    if (uniqueSubUrls.length > 0) {
      const subResponseContent = await getSub(uniqueSubUrls, request, appendUA, userAgentHeader);
      reqData += subResponseContent[0].join('\n');
      subConverterURL += '|' + subResponseContent[1];

      if (subFormat === 'base64' && !isSubConverterRequest && subResponseContent[1].includes('://')) {
        subConverterUrl = `${effectiveSubProtocol}://${effectiveSubConverter}/sub?target=mixed&url=${encodeURIComponent(subResponseContent[1])}&insert=false&config=${encodeURIComponent(effectiveSubConfig)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
        try {
          const subConverterResponse = await fetch(subConverterUrl, {
            headers: { 'User-Agent': 'v2rayN/CF-Workers-SUB  (https://github.com/cmliu/CF-Workers-SUB)' }
          });
          if (subConverterResponse.ok) {
            const subConverterContent = await subConverterResponse.text();
            reqData += '\n' + atob(subConverterContent);
          }
        } catch (error) {
          console.log('订阅转换回base64失败，检查订阅转换后端是否正常运行');
        }
      }
    }

    if (env.WARP) subConverterURL += '|' + (await splitLines(env.WARP)).join('|');

    // ---- 8. 去重 + 编码 ----
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();
    const decoded = decoder.decode(encoder.encode(reqData));
    const uniqueLines = new Set(decoded.split('\n'));
    const result = [...uniqueLines].join('\n');

    let base64Data;
    try {
      base64Data = btoa(result);
    } catch {
      base64Data = encodeBase64Fallback(result);
    }

    // ---- 9. 构建响应 ----
    const responseHeaders = {
      'content-type': 'text/plain; charset=utf-8',
      'Profile-Update-Interval': `${effectiveSubUpdateTime}`,
      'Profile-web-page-url': request.url.includes('?') ? request.url.split('?')[0] : request.url,
    };

    if (subFormat === 'base64' || tokenParam === fakeToken) {
      return new Response(base64Data, { headers: responseHeaders });
    }

    // 非 base64 格式走订阅转换后端
    const targetMap = {
      clash:   `sub?target=clash&url=${encodeURIComponent(subConverterURL)}&insert=false&config=${encodeURIComponent(effectiveSubConfig)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`,
      singbox: `sub?target=singbox&url=${encodeURIComponent(subConverterURL)}&insert=false&config=${encodeURIComponent(effectiveSubConfig)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`,
      surge:   `sub?target=surge&ver=4&url=${encodeURIComponent(subConverterURL)}&insert=false&config=${encodeURIComponent(effectiveSubConfig)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`,
      quanx:   `sub?target=quanx&url=${encodeURIComponent(subConverterURL)}&insert=false&config=${encodeURIComponent(effectiveSubConfig)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&udp=true`,
      loon:    `sub?target=loon&url=${encodeURIComponent(subConverterURL)}&insert=false&config=${encodeURIComponent(effectiveSubConfig)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false`,
    };

    subConverterUrl = `${effectiveSubProtocol}://${effectiveSubConverter}/${targetMap[subFormat] || ''}`;

    try {
      const subConverterResponse = await fetch(subConverterUrl, {
        headers: { 'User-Agent': userAgentHeader }
      });
      if (!subConverterResponse.ok) return new Response(base64Data, { headers: responseHeaders });
      let subConverterContent = await subConverterResponse.text();
      if (subFormat === 'clash') subConverterContent = await clashFix(subConverterContent);
      if (!userAgent.includes('mozilla')) {
        responseHeaders['Content-Disposition'] = `attachment; filename*=utf-8''${encodeURIComponent(effectiveFileName)}`;
      }
      return new Response(subConverterContent, { headers: responseHeaders });
    } catch {
      return new Response(base64Data, { headers: responseHeaders });
    }
  }
};
