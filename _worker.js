/**
 * -----------------------------------------------------------------------------------------
 * Cloudflare Worker: 全能下载代理 & Docker 镜像加速器 (Ultimate Edition)
 * -----------------------------------------------------------------------------------------
 *
 * 【主要功能列表】
 *
 * 1. 🚀 Docker 镜像加速 (核心增强):
 * - 智能路由: 自动识别 Docker 客户端请求 (User-Agent 检测)，CLI 访问免密直连。
 * - 路径补全: 自动为 Docker Hub 官方镜像补全 `library/` 前缀 (如 nginx -> library/nginx)。
 * - 核心修复: 递归追踪 Layer 的 302/307 跳转，智能修复 S3 预签名 URL 的 403 Forbidden 错误。
 * - 多源支持: 完美支持 docker.io, ghcr.io, quay.io, k8s.gcr.io 等主流仓库。
 *
 * 2. ⚡ 通用文件/网页代理:
 * - 权限控制: 访问网页或下载普通文件需通过 `/密码/` 路径验证，防止滥用。
 * - 隐身模式: 访问根目录 `/` 返回 404，只有知道密码才能进入后台。
 * - 内容重写: 自动替换 .sh/.py 脚本中的 URL 为代理链接；自动重写网页中的 href/src。
 * - 流式处理: 支持无限大小的大文件流式传输，内存占用极低。
 * - 防盗链伪装: 自动修改 Referer/Origin/User-Agent，绕过绝大多数网站限制。
 *
 * 3. 🛡️ 安全与防护:
 * - 访问控制: 支持配置 IP 白名单 (ALLOW_IPS) 和 国家/地区限制 (ALLOW_COUNTRIES)。
 * - 目标过滤: 支持配置 域名黑名单 (BLACKLIST) 和 白名单 (WHITELIST)。
 * - 隐私保护: 集成 `robots.txt` 禁止搜索引擎爬虫收录。
 *
 * 4. 🎨 交互体验与细节:
 * - 经典 UI: 双栏设计，上方通用加速(带打开按钮)，下方 Docker 加速(带复制命令)。
 * - 贴心功能: 底部自动生成 Docker Daemon 配置指南；支持 favicon.ico 消除浏览器报错。
 * - 视觉体验: 自动适配 深色/浅色 (Dark/Light) 模式。
 * - 运维监控: 详细的访问日志 (Console Log) 记录。
 *
 * -----------------------------------------------------------------------------------------
 */

const DEFAULT_CONFIG = {
  PASSWORD: "123456",     // 访问密码
  MAX_REDIRECTS: 5,       // 最大重定向次数
  ENABLE_CACHE: true,     // 是否开启缓存
  CACHE_TTL: 3600,        // 缓存时间(秒)
  BLACKLIST: "",          // 黑名单
  WHITELIST: "",          // 白名单
  ALLOW_IPS: "",          // 允许 IP
  ALLOW_COUNTRIES: ""     // 允许国家
};

const DOCKER_REGISTRIES = [
  'docker.io', 'registry-1.docker.io', 'quay.io', 'gcr.io', 'k8s.gcr.io', 
  'registry.k8s.io', 'ghcr.io', 'docker.cloudsmith.io'
];

const LIGHTNING_SVG = `<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M13 2L3 14H12L11 22L21 10H12L13 2Z" stroke="#F59E0B" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>`;

export default {
  async fetch(request, env, ctx) {
    const parseList = (envValue, defaultValue) => {
      return (envValue || defaultValue).split(',').map(s => s.trim()).filter(s => s.length > 0);
    };

    const CONFIG = {
      PASSWORD: env.PASSWORD || DEFAULT_CONFIG.PASSWORD,
      MAX_REDIRECTS: parseInt(env.MAX_REDIRECTS || DEFAULT_CONFIG.MAX_REDIRECTS),
      ENABLE_CACHE: (env.ENABLE_CACHE || "true") === "true",
      CACHE_TTL: parseInt(env.CACHE_TTL || DEFAULT_CONFIG.CACHE_TTL),
      BLACKLIST: parseList(env.BLACKLIST, DEFAULT_CONFIG.BLACKLIST),
      WHITELIST: parseList(env.WHITELIST, DEFAULT_CONFIG.WHITELIST),
      ALLOW_IPS: parseList(env.ALLOW_IPS, DEFAULT_CONFIG.ALLOW_IPS),
      ALLOW_COUNTRIES: parseList(env.ALLOW_COUNTRIES, DEFAULT_CONFIG.ALLOW_COUNTRIES),
    };

    const url = new URL(request.url);

    // --- 0. 细节路由处理 (防爬虫 & 图标) ---
    if (url.pathname === '/robots.txt') {
      return new Response("User-agent: *\nDisallow: /", { headers: { "Content-Type": "text/plain" } });
    }
    if (url.pathname === '/favicon.ico') {
      return new Response(LIGHTNING_SVG, { headers: { "Content-Type": "image/svg+xml" } });
    }

    // --- 1. CORS 预检 ---
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS, HEAD",
          "Access-Control-Allow-Headers": "*",
          "Access-Control-Max-Age": "86400",
          "Docker-Distribution-API-Version": "registry/2.0" 
        },
      });
    }

    // --- 2. 安全检查 ---
    const clientIP = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
    const clientCountry = request.cf ? request.cf.country : "XX"; 
    
    // 日志记录 (方便在后台 Logs 查看)
    console.log(`[Request] ${request.method} ${url.pathname} | IP: ${clientIP} | Country: ${clientCountry} | UA: ${request.headers.get("User-Agent")}`);

    const hasIpConfig = CONFIG.ALLOW_IPS.length > 0;
    const hasCountryConfig = CONFIG.ALLOW_COUNTRIES.length > 0;

    if (hasIpConfig || hasCountryConfig) {
      let isAllowed = false;
      if (hasIpConfig && CONFIG.ALLOW_IPS.includes(clientIP)) isAllowed = true;
      if (!isAllowed && hasCountryConfig && CONFIG.ALLOW_COUNTRIES.includes(clientCountry)) isAllowed = true;
      if (!isAllowed) {
        console.warn(`[Block] Access denied for IP ${clientIP}`);
        return new Response(`Access Denied: IP (${clientIP}) or Country (${clientCountry}) not allowed.`, { status: 403 });
      }
    }

    // --- 3. Docker 路由分流 ---
    const userAgent = (request.headers.get("User-Agent") || "").toLowerCase();
    const isDockerClient = userAgent.includes("docker") || userAgent.includes("go-http");
    
    if (url.pathname.startsWith("/v2/") && isDockerClient) {
      return handleDockerRequest(request, url);
    }

    // --- 4. 通用代理逻辑 ---
    const path = url.pathname;
    const match = path.match(/^\/([^/]+)(?:\/(.*))?$/);
    
    if (!match) return new Response("404 Not Found", { status: 404 });
    
    const inputPassword = match[1];
    let targetUrlStr = match[2];

    if (inputPassword !== CONFIG.PASSWORD) return new Response("404 Not Found", { status: 404 });

    if (!targetUrlStr) {
      return new Response(renderDashboard(url.hostname, CONFIG.PASSWORD), {
        status: 200,
        headers: { "Content-Type": "text/html;charset=UTF-8" }
      });
    }

    if (url.search) targetUrlStr += url.search;
    
    // 缓存处理
    const cacheKey = new Request(url.toString(), request);
    const cache = caches.default;
    if (CONFIG.ENABLE_CACHE && request.method === "GET") {
      let cachedResponse = await cache.match(cacheKey);
      if (cachedResponse) {
        const newHeaders = new Headers(cachedResponse.headers);
        newHeaders.set("X-Proxy-Cache", "HIT");
        return new Response(cachedResponse.body, { status: cachedResponse.status, headers: newHeaders });
      }
    }

    return handleGeneralProxy(request, targetUrlStr, CONFIG, cache, cacheKey, ctx);
  }
};

/** Docker Logic */
async function handleDockerRequest(request, url) {
  let path = url.pathname.replace(/^\/v2\//, '');
  let targetDomain = 'registry-1.docker.io'; 
  let targetPath = path;
  const pathParts = path.split('/');
  
  if (pathParts.length > 0 && (pathParts[0].includes('.') || DOCKER_REGISTRIES.includes(pathParts[0]))) {
      targetDomain = pathParts[0];
      targetPath = pathParts.slice(1).join('/');
  }

  if (targetDomain === 'registry-1.docker.io') {
      const parts = targetPath.split('/');
      if (parts.length > 1 && ['manifests', 'blobs', 'tags'].includes(parts[1])) {
          targetPath = 'library/' + targetPath;
      }
  }

  const targetUrl = `https://${targetDomain}/v2/${targetPath}` + url.search;
  console.log(`[Docker] Proxying to: ${targetUrl}`); // 日志

  const newHeaders = new Headers(request.headers);
  newHeaders.set('Host', targetDomain);
  newHeaders.set('User-Agent', 'Docker-Client/19.03.1 (linux)');
  
  if (isAmazonS3(targetUrl)) {
    newHeaders.set('x-amz-content-sha256', getEmptyBodySHA256());
    newHeaders.set('x-amz-date', new Date().toISOString().replace(/[-:T]/g, '').slice(0, -5) + 'Z');
  }

  try {
    let response = await fetch(targetUrl, {
      method: request.method,
      headers: newHeaders,
      body: request.body,
      redirect: 'manual' 
    });

    if (response.status === 401) {
      const wwwAuth = response.headers.get('WWW-Authenticate');
      if (wwwAuth) {
        const authMatch = wwwAuth.match(/Bearer realm="([^"]+)",service="([^"]*)",scope="([^"]*)"/);
        if (authMatch) {
          const [, realm, service, scope] = authMatch;
          const token = await handleDockerToken(realm, service || targetDomain, scope);
          if (token) {
            const authHeaders = new Headers(newHeaders);
            authHeaders.set('Authorization', `Bearer ${token}`);
            response = await fetch(targetUrl, {
              method: request.method,
              headers: authHeaders,
              body: request.body,
              redirect: 'manual'
            });
          }
        }
      }
    }

    if (response.status === 307 || response.status === 302) {
      const redirectUrl = response.headers.get('Location');
      if (redirectUrl) {
        const redirectHeaders = new Headers(request.headers);
        redirectHeaders.delete('Authorization'); 
        redirectHeaders.set('Host', new URL(redirectUrl).hostname);
        
        const isPresigned = redirectUrl.includes('X-Amz-Signature') || redirectUrl.includes('Signature');
        if (isAmazonS3(redirectUrl) && !isPresigned) {
           redirectHeaders.set('x-amz-content-sha256', getEmptyBodySHA256());
           redirectHeaders.set('x-amz-date', new Date().toISOString().replace(/[-:T]/g, '').slice(0, -5) + 'Z');
        }

        response = await fetch(redirectUrl, {
          method: request.method,
          headers: redirectHeaders,
          body: request.body,
          redirect: 'manual'
        });
      }
    }

    if (!response.ok) {
        const errorBody = await response.text();
        return new Response(errorBody, { status: response.status, headers: response.headers });
    }

    const newResponse = new Response(response.body, response);
    newResponse.headers.set('Access-Control-Allow-Origin', '*');
    newResponse.headers.set('Docker-Distribution-API-Version', 'registry/2.0');
    return newResponse;

  } catch (e) {
    return new Response(JSON.stringify({ errors: [{ message: `Worker Error: ${e.message}` }] }), { status: 500 });
  }
}

async function handleDockerToken(realm, service, scope) {
  const tokenUrl = `${realm}?service=${service}&scope=${scope}`;
  try {
    const res = await fetch(tokenUrl, { headers: { 'Accept': 'application/json' } });
    const data = await res.json();
    return data.token || data.access_token;
  } catch (e) { return null; }
}

function isAmazonS3(url) {
  return url.includes('amazonaws.com') || url.includes('r2.cloudflarestorage.com');
}

function getEmptyBodySHA256() {
  return 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
}

/** General Proxy Handler */
async function handleGeneralProxy(request, targetUrlStr, CONFIG, cache, cacheKey, ctx) {
    let currentUrlStr = targetUrlStr;
    let redirectCount = 0;
    let finalResponse = null;
    const originalHeaders = new Headers(request.headers);

    console.log(`[Proxy] Target: ${targetUrlStr}`); // 日志

    try {
      while (redirectCount < CONFIG.MAX_REDIRECTS) {
        if (!currentUrlStr.startsWith("http")) {
          currentUrlStr = currentUrlStr.replace(/^(https?):\/+/, '$1://');
          if (!currentUrlStr.startsWith('http')) currentUrlStr = 'http://' + currentUrlStr;
        }
        
        let currentTargetUrl;
        try { currentTargetUrl = new URL(currentUrlStr); } catch(e) { return new Response("Invalid URL", {status: 400}); }

        const domain = currentTargetUrl.hostname;
        if (CONFIG.BLACKLIST.some(k => domain.includes(k))) return new Response("Domain Blacklisted", { status: 403 });
        if (CONFIG.WHITELIST.length > 0 && !CONFIG.WHITELIST.some(k => domain.includes(k))) return new Response("Domain Not in Whitelist", { status: 403 });

        const newHeaders = new Headers(originalHeaders);
        newHeaders.set("Host", currentTargetUrl.hostname);
        newHeaders.set("Referer", currentTargetUrl.origin + "/"); 
        newHeaders.set("Origin", currentTargetUrl.origin);
        newHeaders.set("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        
        const originalUA = newHeaders.get("User-Agent");
        if (!originalUA || originalUA.includes("curl") || originalUA.includes("wget")) {
            newHeaders.set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36");
        }
        
        newHeaders.delete("Cf-Worker");
        newHeaders.delete("Cf-Ray");
        newHeaders.delete("Cookie"); 
        newHeaders.delete("X-Forwarded-For");

        const newRequest = new Request(currentUrlStr, {
          method: request.method,
          headers: newHeaders,
          body: request.method !== "GET" && request.method !== "HEAD" ? request.body : null,
          redirect: "manual"
        });

        const response = await fetch(newRequest);

        if ([301, 302, 303, 307, 308].includes(response.status)) {
          const location = response.headers.get("Location");
          if (location) {
            currentUrlStr = new URL(location, currentUrlStr).href;
            redirectCount++;
            continue;
          }
        }
        finalResponse = response;
        break;
      }

      if (!finalResponse) return new Response("Error: Too many redirects", { status: 502 });

      const contentType = finalResponse.headers.get("content-type") || "";
      const proxyBase = `${new URL(request.url).origin}/${CONFIG.PASSWORD}/`; 
      let finalResBody = finalResponse.body;
      let shouldCache = true;

      if (contentType.includes("text/html")) {
        shouldCache = false; 
        return rewriteHtml(finalResponse, proxyBase, currentUrlStr);
      }
      
      if (shouldRewriteScript(contentType, currentUrlStr)) {
        shouldCache = false;
        const { readable, writable } = new TransformStream(new ScriptRewriter(proxyBase));
        finalResponse.body.pipeTo(writable).catch(err => console.log(err));
        const responseHeaders = new Headers(finalResponse.headers);
        responseHeaders.set("Access-Control-Allow-Origin", "*");
        responseHeaders.delete("Content-Length");
        return new Response(readable, { status: finalResponse.status, headers: responseHeaders });
      }

      const responseHeaders = new Headers(finalResponse.headers);
      responseHeaders.set("Access-Control-Allow-Origin", "*");
      responseHeaders.set("X-Proxy-Cache", "MISS");

      if (CONFIG.ENABLE_CACHE && shouldCache && request.method === "GET" && finalResponse.status === 200) {
        const responseToCache = new Response(finalResponse.body, { status: finalResponse.status, headers: responseHeaders });
        responseToCache.headers.set("Cache-Control", `public, max-age=${CONFIG.CACHE_TTL}`);
        const [body1, body2] = finalResponse.body.tee();
        ctx.waitUntil(cache.put(cacheKey, new Response(body1, responseToCache)));
        finalResBody = body2;
      }

      return new Response(finalResBody, { status: finalResponse.status, headers: responseHeaders });

    } catch (e) {
      return new Response(`Proxy Error: ${e.message}`, { status: 500 });
    }
}

function shouldRewriteScript(contentType, url) {
  const isText = contentType.includes("text/") || contentType.includes("application/x-sh") || 
                 contentType.includes("application/javascript") || contentType.includes("application/json");
  const isScriptExt = /\.(sh|py|yaml|yml|txt|js|json|xml|conf|ini)$/i.test(url);
  const isBinary = contentType.includes("application/octet-stream") || contentType.includes("application/zip") ||
                   contentType.includes("image/") || contentType.includes("video/");
  return (isText || isScriptExt) && !isBinary;
}

class ScriptRewriter {
  constructor(proxyBase) {
    this.proxyBase = proxyBase;
    this.buffer = "";
    this.decoder = new TextDecoder("utf-8", { stream: true });
    this.encoder = new TextEncoder();
  }
  transform(chunk, controller) {
    this.buffer += this.decoder.decode(chunk, { stream: true });
    const lastNewlineIndex = this.buffer.lastIndexOf("\n");
    if (lastNewlineIndex !== -1) {
      const completeLines = this.buffer.slice(0, lastNewlineIndex + 1);
      this.buffer = this.buffer.slice(lastNewlineIndex + 1);
      const processed = this.replaceUrls(completeLines);
      controller.enqueue(this.encoder.encode(processed));
    }
  }
  flush(controller) {
    if (this.buffer.length > 0) {
      const processed = this.replaceUrls(this.buffer);
      controller.enqueue(this.encoder.encode(processed));
    }
  }
  replaceUrls(text) {
    const regex = /(https?:\/\/[^\s"';<>]+)/g;
    return text.replace(regex, (match) => {
      if (match.includes(this.proxyBase)) return match;
      return this.proxyBase + match;
    });
  }
}

function rewriteHtml(response, proxyBase, targetUrlStr) {
  const rewriter = new HTMLRewriter()
    .on("a", new AttributeRewriter("href", proxyBase, targetUrlStr))
    .on("img", new AttributeRewriter("src", proxyBase, targetUrlStr))
    .on("link", new AttributeRewriter("href", proxyBase, targetUrlStr))
    .on("script", new AttributeRewriter("src", proxyBase, targetUrlStr))
    .on("form", new AttributeRewriter("action", proxyBase, targetUrlStr));

  const newHeaders = new Headers(response.headers);
  newHeaders.delete("Content-Security-Policy");
  newHeaders.delete("Content-Length");
  newHeaders.set("Access-Control-Allow-Origin", "*");
  return rewriter.transform(response);
}

class AttributeRewriter {
  constructor(attributeName, proxyBase, targetBaseUrl) {
    this.attributeName = attributeName;
    this.proxyBase = proxyBase;
    this.targetBaseUrl = targetBaseUrl;
  }
  element(element) {
    const value = element.getAttribute(this.attributeName);
    if (value && !value.startsWith("mailto:") && !value.startsWith("#") && !value.startsWith("javascript:")) {
      try {
        const absoluteUrl = new URL(value, this.targetBaseUrl).href;
        element.setAttribute(this.attributeName, this.proxyBase + absoluteUrl);
      } catch (e) {}
    }
  }
}

/** UI */
function renderDashboard(hostname, password) {
  return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Cloudflare 加速下载</title>
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,${encodeURIComponent(LIGHTNING_SVG)}">
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    body { min-height: 100vh; display: flex; align-items: center; justify-content: center; font-family: 'Inter', sans-serif; transition: background-color 0.3s, color 0.3s; padding: 1rem; }
    .light-mode { background: linear-gradient(to bottom right, #f1f5f9, #e2e8f0); color: #111827; }
    .dark-mode { background: linear-gradient(to bottom right, #1f2937, #374151); color: #e5e7eb; }
    .container { width: 100%; max-width: 800px; padding: 1.5rem; border-radius: 0.75rem; border: 1px solid #e5e7eb; box-shadow: 0 8px 16px rgba(0, 0, 0, 0.1); }
    .light-mode .container { background: #ffffff; }
    .dark-mode .container { background: #1f2937; border-color: #374151; }
    .section-box { background: linear-gradient(to bottom, #ffffff, #f3f4f6); border-radius: 0.5rem; padding: 1.5rem; margin-bottom: 1.5rem; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1); }
    .dark-mode .section-box { background: linear-gradient(to bottom, #374151, #1f2937); box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2); }
    .theme-toggle { position: fixed; top: 0.5rem; right: 0.5rem; padding: 0.5rem; font-size: 1.2rem; cursor: pointer; }
    .toast { position: fixed; bottom: 1rem; left: 50%; transform: translateX(-50%); padding: 0.75rem 1.5rem; border-radius: 0.5rem; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); opacity: 0; transition: opacity 0.3s; font-size: 0.9rem; max-width: 90%; text-align: center; color: white; z-index: 50; }
    .toast.show { opacity: 1; }
    .result-text { word-break: break-all; overflow-wrap: break-word; font-size: 0.95rem; max-width: 100%; padding: 0.5rem; border-radius: 0.25rem; background: #f3f4f6; }
    .dark-mode .result-text { background: #2d3748; }
    input[type="text"] { background-color: white !important; color: #111827 !important; }
    .dark-mode input[type="text"] { background-color: #374151 !important; color: #e5e7eb !important; }
    @media (max-width: 640px) { .container { padding: 1rem; } .section-box { padding: 1rem; } h1 { font-size: 1.5rem; } }
  </style>
</head>
<body class="light-mode">
  <button onclick="toggleTheme()" class="theme-toggle bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 rounded-full hover:bg-gray-300 dark:hover:bg-gray-600 transition">
    <span class="sun">☀️</span><span class="moon hidden">🌙</span>
  </button>
  <div class="container mx-auto">
    <h1 class="text-3xl font-bold text-center mb-8">Cloudflare 加速下载</h1>

    <div class="section-box">
      <h2 class="text-xl font-semibold mb-2">⚡ GitHub / 通用文件 / IP 加速</h2>
      <p class="text-gray-600 dark:text-gray-300 mb-4">输入 GitHub 文件链接、Raw 文件或纯 IP 下载地址。</p>
      <div class="flex gap-2 mb-2 flex-col sm:flex-row">
        <input id="github-url" type="text" placeholder="https://github.com/user/repo/release.zip 或 http://1.1.1.1/file" class="flex-grow p-2 border border-gray-400 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
        <button onclick="convertGithubUrl()" class="bg-blue-500 text-white px-4 py-2 rounded-lg hover:bg-blue-600 transition whitespace-nowrap">获取加速链接</button>
      </div>
      <p id="github-result" class="mt-2 text-green-600 dark:text-green-400 result-text hidden"></p>
      <div id="github-buttons" class="flex gap-2 mt-2 hidden flex-col sm:flex-row">
        <button onclick="copyGithubUrl()" class="bg-gray-200 dark:bg-gray-600 text-gray-800 dark:text-gray-200 px-3 py-1 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-500 transition w-full">📋 复制链接</button>
        <button onclick="openGithubUrl()" class="bg-gray-200 dark:bg-gray-600 text-gray-800 dark:text-gray-200 px-3 py-1 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-500 transition w-full">🔗 打开链接</button>
      </div>
    </div>

    <div class="section-box">
      <h2 class="text-xl font-semibold mb-2">🐳 Docker 镜像加速</h2>
      <p class="text-gray-600 dark:text-gray-300 mb-4">输入镜像名称 (如 nginx) 或完整地址 (如 ghcr.io/user/image)。</p>
      <div class="flex gap-2 mb-2 flex-col sm:flex-row">
        <input id="docker-image" type="text" placeholder="nginx 或 library/redis" class="flex-grow p-2 border border-gray-400 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
        <button onclick="convertDockerImage()" class="bg-blue-500 text-white px-4 py-2 rounded-lg hover:bg-blue-600 transition whitespace-nowrap">获取加速命令</button>
      </div>
      <p id="docker-result" class="mt-2 text-green-600 dark:text-green-400 result-text hidden"></p>
      <div id="docker-buttons" class="flex gap-2 mt-2 hidden">
        <button onclick="copyDockerCommand()" class="bg-gray-200 dark:bg-gray-600 text-gray-800 dark:text-gray-200 px-3 py-1 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-500 transition w-full">📋 复制命令</button>
      </div>
    </div>

    <div class="section-box">
      <h3 class="text-lg font-bold mb-2">🛠️ 设置为 Docker 镜像源 (推荐)</h3>
      <p class="text-gray-600 dark:text-gray-400 text-sm mb-4">修改配置后，即可直接使用 <code>docker pull nginx</code>，无需输入域名。</p>
      
      <div class="bg-gray-800 text-gray-200 p-3 rounded-lg text-sm font-mono overflow-x-auto mb-3">
        <p class="text-gray-500 mb-1"># 1. 编辑配置文件</p>
        <p class="select-all">nano /etc/docker/daemon.json</p>
        <p class="text-gray-500 mt-2 mb-1"># 2. 填入以下内容</p>
        <pre id="daemon-json-content" class="text-green-400">Loading...</pre>
        <p class="text-gray-500 mt-2 mb-1"># 3. 重启 Docker</p>
        <p class="select-all">sudo systemctl daemon-reload && sudo systemctl restart docker</p>
      </div>
      <button onclick="copyDaemonJson()" class="bg-gray-500 hover:bg-gray-600 text-white px-3 py-1 rounded text-sm transition">📋 复制配置内容</button>
    </div>

    <footer class="mt-6 text-center text-gray-500 dark:text-gray-400 text-sm">
      Powered by Cloudflare Workers
    </footer>
  </div>

  <div id="toast" class="toast bg-green-500"></div>

  <script>
    const currentDomain = window.location.hostname;
    const WORKER_PASSWORD = "${password}"; 
    let githubAcceleratedUrl = '';
    let dockerCommand = '';

    // Initialize Daemon JSON
    const daemonJson = { "registry-mirrors": ["https://" + currentDomain] };
    document.getElementById('daemon-json-content').textContent = JSON.stringify(daemonJson, null, 2);

    function toggleTheme() {
      const body = document.body;
      const sun = document.querySelector('.sun');
      const moon = document.querySelector('.moon');
      if (body.classList.contains('light-mode')) {
        body.classList.remove('light-mode');
        body.classList.add('dark-mode');
        sun.classList.add('hidden');
        moon.classList.remove('hidden');
        localStorage.setItem('theme', 'dark');
      } else {
        body.classList.remove('dark-mode');
        body.classList.add('light-mode');
        moon.classList.add('hidden');
        sun.classList.remove('hidden');
        localStorage.setItem('theme', 'light');
      }
    }
    if (localStorage.getItem('theme') === 'dark') toggleTheme();

    function showToast(message, isError = false) {
      const toast = document.getElementById('toast');
      toast.textContent = message;
      toast.className = 'toast ' + (isError ? 'bg-red-500' : 'bg-green-500') + ' show';
      setTimeout(() => toast.classList.remove('show'), 3000);
    }

    function copyToClipboard(text) {
      if (navigator.clipboard && window.isSecureContext) {
        return navigator.clipboard.writeText(text);
      }
      const textArea = document.createElement("textarea");
      textArea.value = text;
      textArea.style.position = "fixed";
      document.body.appendChild(textArea);
      textArea.focus();
      textArea.select();
      try {
        document.execCommand('copy');
        document.body.removeChild(textArea);
        return Promise.resolve();
      } catch (err) {
        document.body.removeChild(textArea);
        return Promise.reject(err);
      }
    }

    // --- GitHub / IP 处理逻辑 ---
    function convertGithubUrl() {
      let input = document.getElementById('github-url').value.trim();
      const result = document.getElementById('github-result');
      const buttons = document.getElementById('github-buttons');
      
      if (!input) return showToast('请输入链接', true);
      
      if (!input.startsWith('http')) {
          input = 'https://' + input;
      }

      githubAcceleratedUrl = 'https://' + currentDomain + '/' + WORKER_PASSWORD + '/' + input;
      
      result.textContent = '加速链接: ' + githubAcceleratedUrl;
      result.classList.remove('hidden');
      buttons.classList.remove('hidden');
      
      copyToClipboard(githubAcceleratedUrl).then(() => showToast('已复制到剪贴板'));
    }

    function copyGithubUrl() {
      copyToClipboard(githubAcceleratedUrl).then(() => showToast('已复制'));
    }
    function openGithubUrl() {
      window.open(githubAcceleratedUrl, '_blank');
    }

    // --- Docker 处理逻辑 ---
    function convertDockerImage() {
      const input = document.getElementById('docker-image').value.trim();
      const result = document.getElementById('docker-result');
      const buttons = document.getElementById('docker-buttons');
      
      if (!input) return showToast('请输入镜像名', true);
      
      dockerCommand = 'docker pull ' + currentDomain + '/' + input;
      
      result.textContent = '加速命令: ' + dockerCommand;
      result.classList.remove('hidden');
      buttons.classList.remove('hidden');
      copyToClipboard(dockerCommand).then(() => showToast('已复制'));
    }

    function copyDockerCommand() {
      copyToClipboard(dockerCommand).then(() => showToast('已复制'));
    }

    // --- Copy Daemon JSON ---
    function copyDaemonJson() {
       copyToClipboard(JSON.stringify(daemonJson, null, 2)).then(() => showToast('配置已复制'));
    }
  </script>
</body>
</html>
  `;
}
