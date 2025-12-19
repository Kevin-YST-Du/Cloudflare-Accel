/**
 * -----------------------------------------------------------------------------------------
 * Cloudflare Worker: 全能下载代理 & Docker 镜像加速器 (Ultimate Edition)
 * -----------------------------------------------------------------------------------------
 *
 * 【版本说明】
 * 1. [CSS 优化] 样式表已展开为多行，方便阅读和修改。
 * 2. [智能防抖] 10秒内同一IP请求同一镜像Tag只计费1次，解决 Docker 重复扣费问题。
 * 3. [计费回滚] 请求失败自动退还额度。
 * 4. [功能完整] 包含镜像加速、S3 修复、UI 界面、IP 限制等。
 *
 * -----------------------------------------------------------------------------------------
 */

// 配置区域
const DEFAULT_CONFIG = {
  PASSWORD: "123456",             // 访问密码，访问网页时需校验
  MAX_REDIRECTS: 10,              // 最大重定向深度，防止死循环
  ENABLE_CACHE: true,             // 是否开启缓存
  CACHE_TTL: 3600,                // 缓存过期时间 (秒)
  BLACKLIST: "",                  // 域名黑名单 (逗号分隔)
  WHITELIST: "",                  // 域名白名单 (逗号分隔)
  ALLOW_IPS: "",                  // 允许访问的客户端 IP (逗号分隔)
  ALLOW_COUNTRIES: "",            // 允许访问的国家代码 (逗号分隔)
  
  // --- 统计配置 ---
  DAILY_LIMIT_COUNT: 50,          // 每日允许的最大请求次数 (HTML + Docker Manifest)
  
  // IP 白名单列表 (支持多行书写，在此列表内的 IP 不消耗额度)
  IP_LIMIT_WHITELIST: `
  127.0.0.1,
  192.178.1.2
  `, 
};

// Docker 官方及第三方镜像仓库列表
const DOCKER_REGISTRIES = [
  'docker.io', 
  'registry-1.docker.io', 
  'quay.io', 
  'gcr.io', 
  'k8s.gcr.io', 
  'registry.k8s.io', 
  'ghcr.io', 
  'docker.cloudsmith.io'
];

// 网页图标 (SVG)
const LIGHTNING_SVG = `<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M13 2L3 14H12L11 22L21 10H12L13 2Z" stroke="#F59E0B" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>`;

export default {
  async fetch(request, env, ctx) {
    // 辅助函数：解析逗号分隔的字符串为数组
    const parseList = (envValue, defaultValue) => {
      return (envValue || defaultValue).split(',').map(s => s.trim()).filter(s => s.length > 0);
    };

    // 初始化配置，优先读取环境变量
    const CONFIG = {
      PASSWORD: env.PASSWORD || DEFAULT_CONFIG.PASSWORD,
      MAX_REDIRECTS: parseInt(env.MAX_REDIRECTS || DEFAULT_CONFIG.MAX_REDIRECTS),
      ENABLE_CACHE: (env.ENABLE_CACHE || "true") === "true",
      CACHE_TTL: parseInt(env.CACHE_TTL || DEFAULT_CONFIG.CACHE_TTL),
      BLACKLIST: parseList(env.BLACKLIST, DEFAULT_CONFIG.BLACKLIST),
      WHITELIST: parseList(env.WHITELIST, DEFAULT_CONFIG.WHITELIST),
      ALLOW_IPS: parseList(env.ALLOW_IPS, DEFAULT_CONFIG.ALLOW_IPS),
      ALLOW_COUNTRIES: parseList(env.ALLOW_COUNTRIES, DEFAULT_CONFIG.ALLOW_COUNTRIES),
      DAILY_LIMIT_COUNT: parseInt(env.DAILY_LIMIT_COUNT || DEFAULT_CONFIG.DAILY_LIMIT_COUNT),
      IP_LIMIT_WHITELIST: parseList(env.IP_LIMIT_WHITELIST, DEFAULT_CONFIG.IP_LIMIT_WHITELIST),
    };

    const url = new URL(request.url);
    const clientIP = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
    const acceptHeader = (request.headers.get("Accept") || "").toLowerCase();
    const userAgent = (request.headers.get("User-Agent") || "").toLowerCase();
    const isDockerClient = userAgent.includes("docker") || userAgent.includes("go-http");
    const isDockerV2 = url.pathname.startsWith("/v2/");

    // --------------------------------------------------------------------------------
    // 0. 基础静态资源处理 (直接返回，不消耗额度)
    // --------------------------------------------------------------------------------
    if (url.pathname === '/robots.txt') {
      return new Response("User-agent: *\nDisallow: /", { headers: { "Content-Type": "text/plain" } });
    }
    if (url.pathname === '/favicon.ico') {
      return new Response(LIGHTNING_SVG, { headers: { "Content-Type": "image/svg+xml" } });
    }
    
    // CORS 预检请求处理
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

    // --------------------------------------------------------------------------------
    // 1. 安全检查 (IP 和 国家限制)
    // --------------------------------------------------------------------------------
    const clientCountry = request.cf ? request.cf.country : "XX"; 
    const hasIpConfig = CONFIG.ALLOW_IPS.length > 0;
    const hasCountryConfig = CONFIG.ALLOW_COUNTRIES.length > 0;

    if (hasIpConfig || hasCountryConfig) {
      let isAllowed = false;
      if (hasIpConfig && CONFIG.ALLOW_IPS.includes(clientIP)) isAllowed = true;
      if (!isAllowed && hasCountryConfig && CONFIG.ALLOW_COUNTRIES.includes(clientCountry)) isAllowed = true;
      if (!isAllowed) {
        return new Response(`Access Denied: IP (${clientIP}) or Country (${clientCountry}) not allowed.`, { status: 403 });
      }
    }

    // --------------------------------------------------------------------------------
    // 2. 精准计费逻辑 + 智能防抖 (Smart Debounce)
    // --------------------------------------------------------------------------------
    const isWhitelisted = CONFIG.IP_LIMIT_WHITELIST.includes(clientIP);
    let usage = await getIpUsage(clientIP, env, CONFIG);

    const isHtmlRequest = acceptHeader.includes("text/html") && url.pathname.length > (CONFIG.PASSWORD.length + 2);
    
    // 计费判定条件：GET 请求 + Manifests + 非 SHA256 (只计 Tags)
    const isDockerCharge = isDockerV2 
        && isDockerClient 
        && url.pathname.includes("/manifests/") 
        && request.method === "GET"
        && !url.pathname.includes("sha256:");

    let isCharged = false; // 标记本次请求是否实际扣费

    // 如果命中计费条件 且 不在白名单中
    if ((isHtmlRequest || isDockerCharge) && !isWhitelisted) {
      if (usage.count >= CONFIG.DAILY_LIMIT_COUNT) {
        return new Response(`⚠️ 次数超限: IP ${clientIP} 今日已使用 ${usage.count}/${CONFIG.DAILY_LIMIT_COUNT}`, { status: 429 });
      }

      // [核心修复] 检查防抖缓存：如果是10秒内的重复请求，不扣费
      const isDuplicate = await checkIsDuplicate(clientIP, url.pathname);
      
      if (!isDuplicate) {
          // 只有非重复请求才扣费
          await incrementIpUsage(clientIP, env);
          usage.count += 1; 
          isCharged = true; 
          // 设置防抖标记 (异步执行)
          ctx.waitUntil(setDuplicateFlag(clientIP, url.pathname));
      }
    }

    // --------------------------------------------------------------------------------
    // 3. 执行核心业务逻辑 (包裹在 Try-Catch 中以支持回滚)
    // --------------------------------------------------------------------------------
    let response;
    try {
        // Docker 路由分流
        if (url.pathname.startsWith("/v2/") && isDockerClient) {
            response = await handleDockerRequest(request, url);
        } else {
            // 网页/通用代理 路由解析
            const path = url.pathname;
            const match = path.match(/^\/([^/]+)(?:\/(.*))?$/);
            
            // 如果没有匹配到 /密码/ 格式，返回 404
            if (!match || match[1] !== CONFIG.PASSWORD) {
                return new Response("404 Not Found", { status: 404 });
            }

            const targetUrlStr = match[2];

            // 仪表盘渲染 (当没有目标 URL 时)
            if (!targetUrlStr) {
                return new Response(renderDashboard(url.hostname, CONFIG.PASSWORD, clientIP, usage.count, CONFIG.DAILY_LIMIT_COUNT), {
                    status: 200,
                    headers: { "Content-Type": "text/html;charset=UTF-8", "Cache-Control": "no-cache" }
                });
            }

            // 执行通用代理
            const proxyUrl = targetUrlStr + (url.search ? url.search : "");
            const cacheKey = new Request(url.toString(), request);
            const cache = caches.default;

            // 尝试读取缓存
            if (CONFIG.ENABLE_CACHE && request.method === "GET") {
                let cachedResponse = await cache.match(cacheKey);
                if (cachedResponse) {
                    const newHeaders = new Headers(cachedResponse.headers);
                    newHeaders.set("X-Proxy-Cache", "HIT");
                    return new Response(cachedResponse.body, { status: cachedResponse.status, headers: newHeaders });
                }
            }

            response = await handleGeneralProxy(request, proxyUrl, CONFIG, cache, cacheKey, ctx);
        }

        // --------------------------------------------------------------------------------
        // 4. 检查响应状态，决定是否回滚
        // --------------------------------------------------------------------------------
        // 如果已收费，但响应状态码 >= 500 (服务器错误) 或 429 (Too Many Requests)，视为失败，回滚额度
        if (isCharged && response && (response.status >= 500 || response.status === 429)) {
            ctx.waitUntil(decrementIpUsage(clientIP, env)); // 异步回滚
        }

        return response;

    } catch (e) {
        // --------------------------------------------------------------------------------
        // 5. 异常处理与回滚
        // --------------------------------------------------------------------------------
        if (isCharged) {
            await decrementIpUsage(clientIP, env);
        }
        return new Response(JSON.stringify({ 
            error: "Worker Error", 
            message: e.message,
            rollback: isCharged ? "Quota Refunded" : "No Charge" 
        }), { status: 500 });
    }
  }
};

/**
 * -----------------------------------------------------------------------------------------
 * 统计与防抖辅助函数 (基于 Cloudflare KV & Cache API)
 * -----------------------------------------------------------------------------------------
 */

// [防抖] 检查是否为重复请求 (10秒内)
async function checkIsDuplicate(ip, path) {
    const cache = caches.default;
    // 构建一个专用的 Cache Key
    const key = `http://dedup.local/${ip}${path}`; 
    const response = await cache.match(key);
    return !!response; // 如果存在，返回 true
}

// [防抖] 设置重复请求标记
async function setDuplicateFlag(ip, path) {
    const cache = caches.default;
    const key = `http://dedup.local/${ip}${path}`;
    // 存入一个空响应，过期时间 10 秒。足以覆盖 Docker 客户端的 Auth 重试。
    const response = new Response("1", { headers: { "Cache-Control": "max-age=10" } });
    await cache.put(key, response);
}

async function getIpUsage(ip, env, config) {
  if (!env.IP_LIMIT_KV) return { count: 0, allowed: true };
  const today = new Date().toISOString().split('T')[0];
  const key = `limit:${ip}:${today}`;
  try {
    const val = await env.IP_LIMIT_KV.get(key);
    const count = parseInt(val || "0");
    return { count, allowed: count < config.DAILY_LIMIT_COUNT };
  } catch(e) { return { count: 0, allowed: true }; }
}

async function incrementIpUsage(ip, env) {
  if (!env.IP_LIMIT_KV) return;
  const today = new Date().toISOString().split('T')[0];
  const key = `limit:${ip}:${today}`;
  try {
    const val = await env.IP_LIMIT_KV.get(key);
    const current = parseInt(val || "0");
    await env.IP_LIMIT_KV.put(key, (current + 1).toString(), { expirationTtl: 86400 });
  } catch(e) {}
}

async function decrementIpUsage(ip, env) {
    if (!env.IP_LIMIT_KV) return;
    const today = new Date().toISOString().split('T')[0];
    const key = `limit:${ip}:${today}`;
    try {
      const val = await env.IP_LIMIT_KV.get(key);
      let current = parseInt(val || "0");
      if (current > 0) {
        await env.IP_LIMIT_KV.put(key, (current - 1).toString(), { expirationTtl: 86400 });
      }
    } catch(e) {}
}

/**
 * -----------------------------------------------------------------------------------------
 * Docker 核心处理逻辑 (Handle Docker Request)
 * -----------------------------------------------------------------------------------------
 */
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

    const newResponse = new Response(response.body, response);
    newResponse.headers.set('Access-Control-Allow-Origin', '*');
    newResponse.headers.set('Docker-Distribution-API-Version', 'registry/2.0');
    return newResponse;

  } catch (e) {
      throw e; 
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

/**
 * -----------------------------------------------------------------------------------------
 * 通用代理处理器
 * -----------------------------------------------------------------------------------------
 */
async function handleGeneralProxy(request, targetUrlStr, CONFIG, cache, cacheKey, ctx) {
    let currentUrlStr = targetUrlStr;
    
    if (!currentUrlStr.startsWith("http")) {
      currentUrlStr = currentUrlStr.replace(/^(https?):\/+/, '$1://');
      if (!currentUrlStr.startsWith('http')) currentUrlStr = 'https://' + currentUrlStr;
    }

    let redirectCount = 0;
    let finalResponse = null;
    const originalHeaders = new Headers(request.headers);

    try {
      while (redirectCount < CONFIG.MAX_REDIRECTS) {
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

      if (!finalResponse) throw new Error("Too many redirects");

      const contentType = finalResponse.headers.get("content-type") || "";
      const proxyBase = `${new URL(request.url).origin}/${CONFIG.PASSWORD}/`; 
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
        return new Response(body2, { status: finalResponse.status, headers: responseHeaders });
      }

      return new Response(finalResponse.body, { status: finalResponse.status, headers: responseHeaders });

    } catch (e) {
      throw e;
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

/**
 * -----------------------------------------------------------------------------------------
 * 流式重写类：ScriptRewriter
 * -----------------------------------------------------------------------------------------
 */
class ScriptRewriter {
  constructor(proxyBase) {
    this.proxyBase = proxyBase;
    this.buffer = "";
    this.decoder = new TextDecoder("utf-8");
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

/**
 * -----------------------------------------------------------------------------------------
 * HTMLRewriter 处理逻辑
 * -----------------------------------------------------------------------------------------
 */
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

/**
 * -----------------------------------------------------------------------------------------
 * UI 仪表盘 (CSS 已格式化，未压缩)
 * -----------------------------------------------------------------------------------------
 */
function renderDashboard(hostname, password, ip, count, limit) {
  const percent = Math.min(Math.round((count / limit) * 100), 100);
  return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>Cloudflare 加速下载</title>
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,${encodeURIComponent(LIGHTNING_SVG)}">
  
  <script>
    (function() {
      const originalWarn = console.warn;
      console.warn = function(...args) {
        if (args[0] && typeof args[0] === 'string' && args[0].includes('cdn.tailwindcss.com')) return;
        originalWarn.apply(console, args);
      };
    })();
  </script>
  <script src="https://cdn.tailwindcss.com"></script>

  <style>
    body {
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: 'Inter', sans-serif;
      transition: 0.3s;
      padding: 1rem;
      margin: 0;
    }

    .light-mode {
      background: linear-gradient(to bottom right, #f1f5f9, #e2e8f0);
      color: #111827;
    }

    .dark-mode {
      background: linear-gradient(to bottom right, #1f2937, #374151);
      color: #e5e7eb;
    }

    /* 核心布局：电脑端强制 75% 宽度 */
    .custom-content-wrapper {
      width: 75% !important;
      max-width: 1440px !important;
      min-width: 320px;
      padding: 2.5rem;
      border-radius: 1.5rem;
      border: 1px solid #e5e7eb;
      box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1);
      margin: auto;
      transition: all 0.3s ease;
    }

    @media (max-width: 768px) {
      .custom-content-wrapper {
        width: 100% !important;
        padding: 1.25rem;
        margin: 0.5rem;
      }

      h1 {
        font-size: 1.75rem !important;
      }

      .flex-responsive {
        flex-direction: column !important;
      }

      .flex-responsive button {
        width: 100% !important;
        margin-top: 0.75rem;
      }
    }

    .light-mode .custom-content-wrapper {
      background: #ffffff;
    }

    .dark-mode .custom-content-wrapper {
      background: #1f2937;
      border-color: #374151;
    }

    .section-box {
      background: linear-gradient(to bottom, #ffffff, #f3f4f6);
      border-radius: 0.75rem;
      padding: 1.5rem;
      margin-bottom: 1.5rem;
      border: 1px solid rgba(0, 0, 0, 0.05);
    }

    .dark-mode .section-box {
      background: linear-gradient(to bottom, #374151, #1f2937);
      border-color: rgba(255, 255, 255, 0.05);
    }

    .theme-toggle {
      position: fixed;
      top: 1rem;
      right: 1rem;
      padding: 0.6rem;
      font-size: 1.2rem;
      cursor: pointer;
      z-index: 100;
      border-radius: 9999px;
    }

    .toast {
      position: fixed;
      bottom: 2rem;
      left: 50%;
      transform: translateX(-50%);
      padding: 0.75rem 2rem;
      border-radius: 0.75rem;
      z-index: 200;
      color: white;
      opacity: 0;
      transition: 0.3s;
      pointer-events: none;
    }

    .toast.show {
      opacity: 1;
    }

    input[type="text"] {
      border: 1px solid #d1d5db !important;
      transition: 0.2s;
    }

    input[type="text"]:focus {
      border-color: #3b82f6 !important;
      ring: 2px #3b82f6;
    }

    .select-all {
      cursor: pointer;
      user-select: all;
    }

    .select-all:hover {
      opacity: 0.8;
    }
  </style>
</head>
<body class="light-mode">
  <button onclick="toggleTheme()" class="theme-toggle bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 hover:scale-110 transition shadow-lg">
    <span class="sun">☀️</span><span class="moon hidden">🌙</span>
  </button>
  
  <div class="custom-content-wrapper">
    <h1 class="text-3xl font-extrabold text-center mb-6 tracking-tight">Cloudflare 加速下载</h1>
    
    <div class="section-box mb-6 border-b pb-4">
      <div class="flex flex-col md:flex-row justify-between items-center mb-3 gap-2">
        <p class="text-sm font-semibold">当前 IP: <span class="text-blue-500 font-mono">${ip}</span></p>
        <p class="text-sm">今日已用: <span class="font-bold text-blue-600">${count}</span> / ${limit} 次</p>
      </div>
      <div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-1.5 overflow-hidden">
        <div class="bg-blue-600 h-full transition-all duration-1000" style="width: ${percent}%"></div>
      </div>
      <p class="text-[10px] text-gray-400 mt-2 italic text-center">💡 计费说明：请求失败自动退还额度；短时重复请求不扣费。</p>
    </div>

    <div class="section-box">
      <h2 class="text-xl font-bold mb-4 flex items-center gap-2">⚡ GitHub / 通用链接</h2>
      <div class="flex flex-responsive gap-2">
        <input id="github-url" type="text" placeholder="粘贴下载链接..." class="flex-grow p-3 rounded-xl outline-none text-sm dark:bg-gray-800 dark:text-white">
        <button onclick="convertGithubUrl()" class="bg-blue-500 text-white px-6 py-3 rounded-xl hover:bg-blue-600 transition font-bold text-sm whitespace-nowrap shadow-md">获取链接</button>
      </div>
      <p id="github-result" class="mt-4 p-3 text-green-600 dark:text-green-400 bg-green-50 dark:bg-green-900/20 rounded-lg hidden font-mono text-xs break-all border border-green-200 dark:border-green-800"></p>
      <div id="github-buttons" class="flex gap-3 mt-4 hidden">
        <button onclick="copyGithubUrl()" class="flex-1 bg-gray-100 dark:bg-gray-600 text-gray-800 dark:text-gray-200 py-2.5 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-600 transition text-sm font-bold">📋 复制</button>
        <button onclick="openGithubUrl()" class="flex-1 bg-gray-100 dark:bg-gray-600 text-gray-800 dark:text-gray-200 py-2.5 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-600 transition text-sm font-bold">🔗 打开</button>
      </div>
    </div>

    <div class="section-box">
    <h2 class="text-xl font-bold mb-4 flex items-center gap-2">🐳 Docker 镜像加速</h2>
    <div class="flex flex-col md:flex-row gap-2">
      <input id="docker-image" type="text" placeholder="如 nginx 或 library/redis" class="flex-grow p-3 rounded-xl outline-none text-sm dark:bg-gray-800 dark:text-white border border-gray-200 dark:border-gray-600">
      <button onclick="convertDockerImage()" class="bg-blue-500 text-white px-6 py-3 rounded-xl hover:bg-blue-600 transition font-bold text-sm shadow-md">获取命令</button>
    </div>
    
    <p class="text-[12px] text-green-500 mt-2 font-medium">💡 提示：支持 library 自动补全，支持多架构镜像。</p>

    <p id="docker-result" class="mt-4 p-3 text-green-600 dark:text-green-400 bg-green-50 dark:bg-green-900/20 rounded-lg hidden font-mono text-xs break-all border border-green-200 dark:border-green-800"></p>
    <div id="docker-buttons" class="flex gap-2 mt-4 hidden">
      <button onclick="copyDockerCommand()" class="w-full bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-200 py-2.5 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-600 transition text-sm font-bold">📋 复制命令</button>
    </div>
  </div>

    <div class="section-box">
      <h3 class="text-lg font-bold mb-3 tracking-tight">🛠️ 镜像源设置</h3>
      <div class="bg-gray-900 text-gray-300 p-5 rounded-xl text-[11px] font-mono overflow-x-auto mb-4 leading-relaxed border border-gray-800">
        <p class="text-gray-500 mb-1"># 1. 编辑配置文件</p>
        <p class="select-all">nano /etc/docker/daemon.json</p>
        <p class="text-gray-500 mt-2 mb-1"># 2. 填入以下内容</p>
        <pre id="daemon-json-content" class="text-emerald-400 py-2">Loading...</pre>
        <p class="text-gray-500 mt-2 mb-1"># 3. 重启 Docker</p>
        <p class="select-all">sudo systemctl daemon-reload && sudo systemctl restart docker</p>
      </div>
      <button onclick="copyDaemonJson()" class="bg-gray-500 hover:bg-gray-600 text-white px-4 py-2 rounded-lg text-xs transition font-bold shadow-sm">📋 复制 JSON 配置内容</button>
    </div>

    <footer class="mt-8 text-center text-gray-400 text-[10px] uppercase tracking-widest font-bold">
      Powered by Cloudflare Workers & KV Storage
    </footer>
  </div>

  <div id="toast" class="toast bg-green-500 shadow-2xl"></div>

  <script>
    const currentDomain = window.location.hostname;
    const WORKER_PASSWORD = "${password}"; 
    let githubAcceleratedUrl = '';
    let dockerCommand = '';
    
    // 生成多行缩进 JSON
    const daemonJsonObj = { "registry-mirrors": ["https://" + currentDomain] };
    const daemonJsonStr = JSON.stringify(daemonJsonObj, null, 2);
    document.getElementById('daemon-json-content').textContent = daemonJsonStr;

    function toggleTheme() {
      const body = document.body;
      const sun = document.querySelector('.sun');
      const moon = document.querySelector('.moon');
      if (body.classList.contains('light-mode')) {
        body.classList.remove('light-mode');
        body.classList.add('dark-mode');
        sun.classList.add('hidden'); moon.classList.remove('hidden');
        localStorage.setItem('theme', 'dark');
      } else {
        body.classList.remove('dark-mode');
        body.classList.add('light-mode');
        moon.classList.add('hidden'); sun.classList.remove('hidden');
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
      textArea.value = text; textArea.style.position = "fixed";
      document.body.appendChild(textArea); textArea.focus(); textArea.select();
      try { document.execCommand('copy'); document.body.removeChild(textArea); return Promise.resolve(); } 
      catch (err) { document.body.removeChild(textArea); return Promise.reject(err); }
    }

    function convertGithubUrl() {
      let input = document.getElementById('github-url').value.trim();
      const result = document.getElementById('github-result');
      const buttons = document.getElementById('github-buttons');
      if (!input) return showToast('请输入链接', true);
      if (!input.startsWith('http')) { input = 'https://' + input; }
      githubAcceleratedUrl = window.location.origin + '/' + WORKER_PASSWORD + '/' + input;
      result.textContent = githubAcceleratedUrl;
      result.classList.remove('hidden'); buttons.classList.remove('hidden');
      copyToClipboard(githubAcceleratedUrl).then(() => showToast('已复制到剪贴板'));
    }

    function copyGithubUrl() { copyToClipboard(githubAcceleratedUrl).then(() => showToast('已复制')); }
    function openGithubUrl() { window.open(githubAcceleratedUrl, '_blank'); }

    function convertDockerImage() {
      const input = document.getElementById('docker-image').value.trim();
      const result = document.getElementById('docker-result');
      const buttons = document.getElementById('docker-buttons');
      if (!input) return showToast('请输入镜像名', true);
      dockerCommand = 'docker pull ' + currentDomain + '/' + input;
      result.textContent = dockerCommand;
      result.classList.remove('hidden'); buttons.classList.remove('hidden');
      copyToClipboard(dockerCommand).then(() => showToast('已复制'));
    }
    function copyDockerCommand() { copyToClipboard(dockerCommand).then(() => showToast('已复制')); }
    function copyDaemonJson() { copyToClipboard(daemonJsonStr).then(() => showToast('JSON 配置已复制')); }
  </script>
</body>
</html>
  `;
}
