/**
 * -----------------------------------------------------------------------------------------
 * Cloudflare Worker: 终极 Docker 代理 (Ultimate Fixed Version)
 * -----------------------------------------------------------------------------------------
 * * 集成修复：
 * 1. [S3直连] 修复 vaultwarden 等第三方镜像拉取时卡在 Waiting 的问题 (重定向清洗)。
 * 2. [Auth修复] 修复 Token 获取失败，彻底清洗 CF 头 + 伪装最新 Docker 客户端 UA。
 * 3. [路径补全] 智能判断 library/ 前缀，同时支持官方镜像和多段式个人镜像。
 * * -----------------------------------------------------------------------------------------
 */

// ==============================================================================
// 1. 用户配置区域
// ==============================================================================
const DEFAULT_CONFIG = {
    PASSWORD: "123456",               // 访问密码
    MAX_REDIRECTS: 10,                // 最大重定向深度
    ENABLE_CACHE: true,               // 是否开启缓存
    CACHE_TTL: 3600,                  // 缓存时间 (秒)
    BLACKLIST: "",                    // 域名黑名单
    WHITELIST: "",                    // 域名白名单
    ALLOW_IPS: "",                    // 允许访问的客户端 IP
    ALLOW_COUNTRIES: "",              // 允许访问的国家代码
    
    // --- 统计配置 ---
    DAILY_LIMIT_COUNT: 50,            // 每日允许的最大请求次数
    
    // 管理员 IP 列表 (逗号分隔)，用于手动重置
    ADMIN_IPS: `
    127.0.0.1
    `,                    
    // IP 白名单列表 (不消耗额度)
    IP_LIMIT_WHITELIST: `
    127.0.0.1
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

// 多 Hub 路由映射
const REGISTRY_MAP = {
    'ghcr.io': 'https://ghcr.io',
    'quay.io': 'https://quay.io',
    'gcr.io': 'https://gcr.io',
    'k8s.gcr.io': 'https://k8s.gcr.io',
    'registry.k8s.io': 'https://registry.k8s.io',
    'docker.cloudsmith.io': 'https://docker.cloudsmith.io',
    'nvcr.io': 'https://nvcr.io'
};

// 网页图标 (SVG)
const LIGHTNING_SVG = `<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M13 2L3 14H12L11 22L21 10H12L13 2Z" stroke="#F59E0B" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>`;

export default {
    async fetch(request, env, ctx) {
        // 辅助函数
        const parseList = (envValue, defaultValue) => {
            return (envValue || defaultValue).split(',').map(s => s.trim()).filter(s => s.length > 0);
        };

        // 初始化配置
        const CONFIG = {
            PASSWORD: env.PASSWORD || DEFAULT_CONFIG.PASSWORD,
            ADMIN_IPS: parseList(env.ADMIN_IPS, DEFAULT_CONFIG.ADMIN_IPS),
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
        
        // 识别是否为 Docker 客户端 (增加 buildkit 识别)
        const isDockerClient = userAgent.includes("docker") || userAgent.includes("go-http") || userAgent.includes("containerd") || userAgent.includes("buildkit");
        const isDockerV2 = url.pathname.startsWith("/v2/");

        // --------------------------------------------------------------------------------
        // 0. 基础静态资源处理
        // --------------------------------------------------------------------------------
        if (url.pathname === '/robots.txt') {
            return new Response("User-agent: *\nDisallow: /", { headers: { "Content-Type": "text/plain" } });
        }
        if (url.pathname === '/favicon.ico') {
            return new Response(LIGHTNING_SVG, { headers: { "Content-Type": "image/svg+xml" } });
        }

        // ==============================================================================
        // 【核心规则 3】Auth 劫持 (/token)
        // ==============================================================================
        if (url.pathname === '/token') {
            return handleTokenRequest(request, url);
        }

        // CORS 预检
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
        // 1. 安全检查
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
        // 2. 计费逻辑
        // --------------------------------------------------------------------------------
        const isWhitelisted = CONFIG.IP_LIMIT_WHITELIST.includes(clientIP);
        let usage = await getIpUsage(clientIP, env, CONFIG);

        const isHtmlRequest = acceptHeader.includes("text/html") && url.pathname.length > (CONFIG.PASSWORD.length + 2);
        
        // 计费判定
        const isDockerCharge = isDockerV2 
            && isDockerClient 
            && url.pathname.includes("/manifests/") 
            && request.method === "GET"
            && !url.pathname.includes("sha256:");

        let isCharged = false;

        if ((isHtmlRequest || isDockerCharge) && !isWhitelisted) {
            if (usage.count >= CONFIG.DAILY_LIMIT_COUNT) {
                return new Response(`⚠️ 次数超限: IP ${clientIP} 今日已使用 ${usage.count}/${CONFIG.DAILY_LIMIT_COUNT}`, { status: 429 });
            }
            const isDuplicate = await checkIsDuplicate(clientIP, url.pathname);
            if (!isDuplicate) {
                await incrementIpUsage(clientIP, env);
                usage.count += 1;
                isCharged = true;
                ctx.waitUntil(setDuplicateFlag(clientIP, url.pathname));
            }
        }

        // --------------------------------------------------------------------------------
        // 3. 业务逻辑分流
        // --------------------------------------------------------------------------------
        let response;
        try {
            if (isDockerV2) {
                // 只要是 V2 路径，全部交给 Docker 处理逻辑 (确保 docker build 兼容)
                response = await handleDockerRequest(request, url);
            } else {
                // 网页/通用代理逻辑
                const path = url.pathname;
                const match = path.match(/^\/([^/]+)(?:\/(.*))?$/);
                
                if (!match || match[1] !== CONFIG.PASSWORD) {
                    return new Response("404 Not Found", { status: 404 });
                }

                const targetUrlStr = match[2];

                if (targetUrlStr === "reset") {
                    if (CONFIG.ADMIN_IPS.length === 0) return new Response(JSON.stringify({ status: "error", message: "No Admin IPs" }), { status: 403 });
                    if (!CONFIG.ADMIN_IPS.includes(clientIP)) return new Response(JSON.stringify({ status: "error", message: "Forbidden" }), { status: 403 });
                    await resetIpUsage(clientIP, env);
                    return new Response(JSON.stringify({ status: "success", message: "Reset OK" }), { status: 200 });
                }

                if (!targetUrlStr) {
                    return new Response(renderDashboard(url.hostname, CONFIG.PASSWORD, clientIP, usage.count, CONFIG.DAILY_LIMIT_COUNT), {
                        status: 200,
                        headers: { "Content-Type": "text/html;charset=UTF-8", "Cache-Control": "no-cache" }
                    });
                }

                const proxyUrl = targetUrlStr + (url.search ? url.search : "");
                const cacheKey = new Request(url.toString(), request);
                const cache = caches.default;

                if (CONFIG.ENABLE_CACHE && request.method === "GET") {
                    let cachedResponse = await cache.match(cacheKey);
                    if (cachedResponse) {
                        const newHeaders = new Headers(cachedResponse.headers);
                        newHeaders.set("X-Proxy-Cache", "HIT");
                        // 确保缓存的响应也没有 CSP
                        newHeaders.delete("Content-Security-Policy"); 
                        newHeaders.delete("content-security-policy");
                        return new Response(cachedResponse.body, { status: cachedResponse.status, headers: newHeaders });
                    }
                }

                response = await handleGeneralProxy(request, proxyUrl, CONFIG, cache, cacheKey, ctx);
            }

            if (isCharged && response && (response.status >= 500 || response.status === 429)) {
                ctx.waitUntil(decrementIpUsage(clientIP, env));
            }

            return response;

        } catch (e) {
            if (isCharged) await decrementIpUsage(clientIP, env);
            return new Response(JSON.stringify({ error: "Worker Error", message: e.message }), { status: 500 });
        }
    }
};

/**
 * ==============================================================================
 * 核心逻辑：Token 请求处理 (修复：清洗 Header + 伪装 UA)
 * ==============================================================================
 */
async function handleTokenRequest(request, url) {
    const scope = url.searchParams.get('scope');
    const service = url.searchParams.get('service');
    
    let upstreamAuthUrl = 'https://auth.docker.io/token'; 
    
    // 1. 多 Hub 自动识别 Auth
    if (scope) {
        for (const [domain, registryUrl] of Object.entries(REGISTRY_MAP)) {
            if (scope.includes(domain)) {
                upstreamAuthUrl = `https://${domain}/token`;
                break;
            }
        }
    }

    const newUrl = new URL(upstreamAuthUrl);
    newUrl.search = url.search;

    // 2. 针对 Docker Hub 的强制伪装
    if (upstreamAuthUrl === 'https://auth.docker.io/token') {
        newUrl.searchParams.set('service', 'registry.docker.io');
        
        // 强制 Scope 补全逻辑
        if (scope && scope.startsWith('repository:')) {
            const parts = scope.split(':');
            if (parts.length >= 3 && !parts[1].includes('/') && !Object.keys(REGISTRY_MAP).some(d => parts[1].startsWith(d))) {
                parts[1] = 'library/' + parts[1];
                newUrl.searchParams.set('scope', parts.join(':'));
            }
        }
    }

    // 【关键修复】重建 Headers，剔除 Cloudflare 痕迹，伪装 UA
    const newHeaders = new Headers(request.headers);
    newHeaders.set('Host', newUrl.hostname);
    // 伪装成最新的 Docker 客户端，防止 Auth 服务拦截
    newHeaders.set('User-Agent', 'Docker-Client/24.0.5 (linux)');
    newHeaders.set('Accept', 'application/json');
    
    // 剔除敏感头，防止 auth.docker.io 判定为代理请求而拒绝
    newHeaders.delete('Cf-Connecting-Ip');
    newHeaders.delete('Cf-Ray');
    newHeaders.delete('X-Forwarded-For');
    newHeaders.delete('Cookie');
    newHeaders.delete('Cf-Worker');

    const authRequest = new Request(newUrl, {
        method: request.method,
        headers: newHeaders, // 使用清洗后的 Headers
        redirect: 'follow'
    });
    
    return fetch(authRequest);
}

/**
 * ==============================================================================
 * 核心逻辑：Registry 请求处理 (强力正则补全 + S3 重定向修复)
 * ==============================================================================
 */
async function handleDockerRequest(request, url) {
    let path = url.pathname.replace(/^\/v2\//, '');
    let targetDomain = 'registry-1.docker.io'; 
    let upstream = 'https://registry-1.docker.io';
    
    // 0. 特殊处理：/v2/ 根请求
    if (path === '' || path === '/') {
        const rootUrl = 'https://registry-1.docker.io/v2/';
        const rootReq = new Request(rootUrl, { method: request.method, headers: request.headers });
        rootReq.headers.set('Host', 'registry-1.docker.io');
        const rootResp = await fetch(rootReq);
        if (rootResp.status === 401) {
            const authHeader = rootResp.headers.get('WWW-Authenticate');
            if (authHeader) {
                const newResp = new Response(rootResp.body, rootResp);
                const workerOrigin = new URL(request.url).origin;
                const re = /realm="([^"]+)"/;
                const newAuthHeader = authHeader.replace(re, `realm="${workerOrigin}/token"`);
                newResp.headers.set("Www-Authenticate", newAuthHeader);
                return newResp;
            }
        }
        return rootResp;
    }

    // 1. 多 Hub 自动识别
    const pathParts = path.split('/');
    const potentialDomain = pathParts[0];

    if (REGISTRY_MAP[potentialDomain]) {
        targetDomain = potentialDomain;
        upstream = REGISTRY_MAP[potentialDomain];
        path = pathParts.slice(1).join('/');
    }

    // 2. Docker Hub 强制补全 (精准逻辑：仅对单名镜像补全 library/)
    if (targetDomain === 'registry-1.docker.io') {
        const parts = path.split('/');
        // 索引说明: 0=ImageName, 1=manifests/blobs
        // 如果 1 是 API 关键字，说明 ImageName 只有一段，需要补全 library/
        const apiIndex = parts.findIndex(part => ['manifests', 'blobs', 'tags'].includes(part));
        if (apiIndex === 1) {
            path = 'library/' + path;
        }
    }

    const targetUrl = `${upstream}/v2/${path}` + url.search;
    const newHeaders = new Headers(request.headers);
    newHeaders.set('Host', targetDomain);
    newHeaders.set('User-Agent', 'Docker-Client/24.0.5 (linux)'); // 伪装最新 UA
    newHeaders.delete('Cf-Connecting-Ip');
    newHeaders.delete('Cf-Ray');
    
    // 【已移除 S3 签名逻辑】
    // 防止 Worker 试图签名导致与亚马逊原版签名冲突，直接让 Docker 客户端处理

    try {
        let response = await fetch(targetUrl, {
            method: request.method,
            headers: newHeaders,
            body: request.body,
            redirect: 'manual' // 禁止 fetch 自动跟随重定向
        });

        // 3. 劫持 401 响应 (修改 Www-Authenticate 指向我们的 Token 服务)
        if (response.status === 401) {
            const authHeader = response.headers.get('WWW-Authenticate');
            if (authHeader) {
                const newResponse = new Response(response.body, response);
                const workerOrigin = new URL(request.url).origin;
                const re = /realm="([^"]+)"/;
                const newAuthHeader = authHeader.replace(re, `realm="${workerOrigin}/token"`);
                
                newResponse.headers.set("Www-Authenticate", newAuthHeader);
                newResponse.headers.set('Access-Control-Allow-Origin', '*');
                return newResponse;
            }
        }

        // 4. 处理重定向 (核心修复：纯净 Location 返回)
        // 彻底解决 S3 签名问题，让 Docker 客户端直连 AWS 下载
// 替换后的代码
        if ([301, 302, 303, 307, 308].includes(response.status)) {
        const location = response.headers.get('Location');
        if (location) {
        // 让 Worker 顺着重定向地址去抓取真实数据
                const redirectedRequest = new Request(location, {
                method: 'GET',
                headers: newHeaders // 使用之前清洗过的 Headers
            });
                return fetch(redirectedRequest); 
    }
}

        const finalResponse = new Response(response.body, response);
        finalResponse.headers.set('Access-Control-Allow-Origin', '*');
        finalResponse.headers.set('Docker-Distribution-API-Version', 'registry/2.0');
        return finalResponse;

    } catch (e) {
        throw e;
    }
}

// -----------------------------------------------------------------------------------------
// 辅助函数
// -----------------------------------------------------------------------------------------

function getBeijingDateString() {
    return new Date(new Date().getTime() + 28800000).toISOString().split('T')[0];
}

async function checkIsDuplicate(ip, path) {
    const cache = caches.default;
    const key = `http://dedup.local/${ip}${path}`; 
    const response = await cache.match(key);
    return !!response; 
}

async function setDuplicateFlag(ip, path) {
    const cache = caches.default;
    const key = `http://dedup.local/${ip}${path}`;
    const response = new Response("1", { headers: { "Cache-Control": "max-age=10" } });
    await cache.put(key, response);
}

async function getIpUsage(ip, env, config) {
    if (!env.IP_LIMIT_KV) return { count: 0, allowed: true };
    const today = getBeijingDateString(); 
    const key = `limit:${ip}:${today}`;
    try {
        const val = await env.IP_LIMIT_KV.get(key);
        const count = parseInt(val || "0");
        return { count, allowed: count < config.DAILY_LIMIT_COUNT };
    } catch(e) { return { count: 0, allowed: true }; }
}

async function incrementIpUsage(ip, env) {
    if (!env.IP_LIMIT_KV) return;
    const today = getBeijingDateString(); 
    const key = `limit:${ip}:${today}`;
    try {
        const val = await env.IP_LIMIT_KV.get(key);
        const current = parseInt(val || "0");
        await env.IP_LIMIT_KV.put(key, (current + 1).toString(), { expirationTtl: 86400 });
    } catch(e) {}
}

async function decrementIpUsage(ip, env) {
    if (!env.IP_LIMIT_KV) return;
    const today = getBeijingDateString(); 
    const key = `limit:${ip}:${today}`;
    try {
        const val = await env.IP_LIMIT_KV.get(key);
        let current = parseInt(val || "0");
        if (current > 0) {
            await env.IP_LIMIT_KV.put(key, (current - 1).toString(), { expirationTtl: 86400 });
        }
    } catch(e) {}
}

async function resetIpUsage(ip, env) {
    if (!env.IP_LIMIT_KV) return;
    const today = getBeijingDateString(); 
    const key = `limit:${ip}:${today}`;
    try {
        await env.IP_LIMIT_KV.delete(key);
    } catch(e) {}
}

// -----------------------------------------------------------------------------------------
// 通用代理处理器 (重点修改了这里的 CSP 处理)
// -----------------------------------------------------------------------------------------
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
            // 【FIXED】移除 CSP 以允许脚本执行
            const responseHeaders = new Headers(finalResponse.headers);
            responseHeaders.delete("Content-Security-Policy");
            responseHeaders.delete("content-security-policy");
            responseHeaders.delete("X-Content-Security-Policy");
            responseHeaders.set("Access-Control-Allow-Origin", "*");
            responseHeaders.delete("Content-Length");

            const { readable, writable } = new TransformStream(new ScriptRewriter(proxyBase));
            finalResponse.body.pipeTo(writable).catch(err => console.log(err));
            
            return new Response(readable, { status: finalResponse.status, headers: responseHeaders });
        }

        const responseHeaders = new Headers(finalResponse.headers);
        responseHeaders.set("Access-Control-Allow-Origin", "*");
        responseHeaders.set("X-Proxy-Cache", "MISS");
        
        // 【FIXED】移除 CSP 以允许资源加载 (CSS/IMG/Fonts)
        responseHeaders.delete("Content-Security-Policy");
        responseHeaders.delete("content-security-policy");
        responseHeaders.delete("X-Content-Security-Policy");
        responseHeaders.delete("Strict-Transport-Security");

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

// -----------------------------------------------------------------------------------------
// HTML重写与UI
// -----------------------------------------------------------------------------------------
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

function rewriteHtml(response, proxyBase, targetUrlStr) {
    const rewriter = new HTMLRewriter()
        .on("a", new AttributeRewriter("href", proxyBase, targetUrlStr))
        .on("img", new AttributeRewriter("src", proxyBase, targetUrlStr))
        .on("link", new AttributeRewriter("href", proxyBase, targetUrlStr))
        .on("script", new AttributeRewriter("src", proxyBase, targetUrlStr))
        .on("form", new AttributeRewriter("action", proxyBase, targetUrlStr));

    // 【FIXED】正确处理响应头
    const newHeaders = new Headers(response.headers);
    newHeaders.delete("Content-Security-Policy");
    newHeaders.delete("content-security-policy");
    newHeaders.delete("X-Content-Security-Policy");
    newHeaders.delete("X-WebKit-CSP");
    newHeaders.delete("Strict-Transport-Security");
    
    newHeaders.delete("Content-Length");
    newHeaders.set("Access-Control-Allow-Origin", "*");
    
    // 注意：HTMLRewriter.transform 返回的 Response 会继承原有的 headers，
    // 我们必须用新的 headers 重新包装一次，才能确保 delete 生效。
    const transformedResponse = rewriter.transform(response);
    
    return new Response(transformedResponse.body, {
        status: transformedResponse.status,
        headers: newHeaders
    });
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

// -----------------------------------------------------------------------------------------
// Dashboard 渲染函数 (完整保留)
// -----------------------------------------------------------------------------------------
function renderDashboard(hostname, password, ip, count, limit) {
    const percent = Math.min(Math.round((count / limit) * 100), 100);
    
    return `
  <!DOCTYPE html>
  <html lang="zh-CN">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Cloudflare 加速通道</title>
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
      /* 全局设置 */
      body {
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        transition: background-color 0.3s ease;
        padding: 1rem;
        margin: 0;
      }
  
      /* === 亮色模式 (保持清爽) === */
      .light-mode {
        background-color: #f3f4f6;
        color: #1f293b;
      }
      .light-mode .custom-content-wrapper {
        background: white;
        border: 1px solid #e5e7eb;
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.05);
      }
      .light-mode .section-box {
        background: #f8fafc;
        border: 1px solid #e2e8f0;
      }
      .light-mode input {
        background: white;
        border: 1px solid #d1d5db;
        color: #1f293b;
      }
      .light-mode .code-area {
        background: #f1f5f9; border: 1px solid #e2e8f0; color: #334155;
      }
      .light-mode .reset-btn {
          background: #fee2e2; color: #ef4444; border: 1px solid #fca5a5;
      }
  
      /* === 暗黑模式 (还原截图 Deep Slate 风格) === */
      .dark-mode {
        background-color: #0f172a; /* Slate 900 - 页面背景 */
        color: #e2e8f0;
      }
      .dark-mode .custom-content-wrapper {
        background: transparent; /* 容器透明，突出内部卡片 */
        border: none;
        box-shadow: none;
      }
      /* 卡片风格 - 对应截图中的深色块 */
      .dark-mode .section-box {
        background-color: #1e293b; /* Slate 800 - 卡片背景 */
        border: 1px solid #334155; /* Slate 700 - 微弱边框 */
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
      }
      /* 输入框 - 对应截图3的深色底蓝边框风格 */
      .dark-mode input {
        background-color: #0f172a; /* Slate 900 */
        border: 1px solid #3b82f6; /* Blue 500 */
        color: #f1f5f9;
      }
      .dark-mode input::placeholder {
        color: #64748b;
      }
      /* 修复：暗黑模式代码块背景 (Dark Terminal Style) */
      .dark-mode .code-area {
        background-color: #020617; /* Slate 950 (接近纯黑) */
        border: 1px solid #1e293b;
        color: #e2e8f0;
      }
      
      /* 核心修复：添加 select-text 允许选择 */
      .code-area, pre, .select-all {
          user-select: text !important;
          -webkit-user-select: text !important;
      }
      
      /* 重置按钮 - 对应截图2的白色底风格 */
      .dark-mode .reset-btn {
          background-color: white;
          color: #ef4444; /* Red 500 */
          border: none;
          box-shadow: 0 2px 4px rgba(0,0,0,0.1);
      }
      .dark-mode .reset-btn:hover {
          background-color: #f1f5f9;
      }
  
      /* =========== 布局样式 =========== */
      .custom-content-wrapper {
        width: 80% !important;
        max-width: 1200px !important;
        min-width: 320px;
        margin: auto;
        padding: 1rem;
        border-radius: 1.5rem;
      }
  
      @media (max-width: 768px) {
        .custom-content-wrapper { width: 100% !important; padding: 0.5rem; }
        .section-box { padding: 1.25rem !important; }
        .flex-responsive { flex-direction: column !important; gap: 0.75rem !important; }
        .flex-responsive button { width: 100% !important; }
      }
  
      .section-box {
        border-radius: 1rem;
        padding: 2rem;
        margin-bottom: 1.5rem;
        transition: all 0.2s;
      }
  
      .theme-toggle {
        position: fixed; top: 1.5rem; right: 1.5rem;
        padding: 0.5rem; border-radius: 9999px;
        background: rgba(255,255,255,0.1);
        backdrop-filter: blur(4px);
        cursor: pointer; z-index: 50;
        border: 1px solid rgba(255,255,255,0.1);
      }
  
      /* Toast */
      .toast {
        position: fixed; bottom: 3rem; left: 50%;
        transform: translateX(-50%) translateY(20px);
        padding: 0.75rem 1.5rem; border-radius: 0.5rem;
        z-index: 100; color: white; opacity: 0;
        transition: all 0.3s; pointer-events: none;
        font-weight: 500; font-size: 0.9rem;
        box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3);
        display: flex; align-items: center; gap: 0.5rem;
      }
      .toast.show { opacity: 1; transform: translateX(-50%) translateY(0); }
  
      input { outline: none; transition: all 0.2s; }
      input:focus { ring: 2px #3b82f6; ring-offset-2px; }
      .dark-mode input:focus { ring: 0; border-color: #60a5fa; box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.3); }
  
      /* Modal */
      .modal-overlay {
        position: fixed; inset: 0; z-index: 999;
        background: rgba(0, 0, 0, 0.6); /* 更深的遮罩 */
        backdrop-filter: blur(4px);
        display: flex; align-items: center; justify-content: center;
        opacity: 0; pointer-events: none; transition: opacity 0.2s;
      }
      .modal-overlay.open { opacity: 1; pointer-events: auto; }
      .modal-content {
        background: white; width: 90%; max-width: 400px;
        padding: 2rem; border-radius: 1rem;
        box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1);
        transform: scale(0.95); transition: transform 0.2s;
      }
      .modal-overlay.open .modal-content { transform: scale(1); }
      .dark-mode .modal-content { background: #1e293b; border: 1px solid #334155; color: #f1f5f9; }
    </style>
  </head>
  <body class="light-mode">
    <button onclick="toggleTheme()" class="theme-toggle text-gray-500 dark:text-gray-300">
      <span class="sun text-xl">☀️</span><span class="moon hidden text-xl">🌙</span>
    </button>
    
    <div class="custom-content-wrapper">
      <h1 class="text-3xl md:text-4xl font-extrabold text-center mb-8 tracking-tight">
        <span class="bg-clip-text text-transparent bg-gradient-to-r from-blue-600 to-indigo-600 dark:from-blue-400 dark:to-indigo-400">
          Cloudflare 加速通道
        </span>
      </h1>
      
      <div class="section-box relative">
        <div class="flex flex-col md:flex-row justify-between items-center mb-4 gap-4">
          <div class="flex items-center gap-3">
             <div class="relative flex h-3 w-3">
                <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                <span class="relative inline-flex rounded-full h-3 w-3 bg-green-500"></span>
             </div>
             <p class="text-sm font-bold opacity-90 tracking-wide">IP: <span class="font-mono text-blue-600 dark:text-blue-400">${ip}</span></p>
          </div>
          
          <div class="flex items-center gap-4 w-full md:w-auto justify-between md:justify-end">
              <div class="text-sm font-medium opacity-80">
                  今日额度: <span class="text-blue-600 dark:text-blue-400 font-bold">${count}</span> <span class="opacity-50">/ ${limit}</span>
              </div>
              <button onclick="openModal()" class="reset-btn px-3 py-1.5 rounded-lg text-xs font-bold transition-transform hover:scale-105 flex items-center gap-1.5 shadow-sm">
              <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
              </svg>
                  <span>重置额度</span>
              </button>
          </div>
        </div>
        
        <div class="w-full bg-gray-200 dark:bg-slate-700 rounded-full h-2.5 overflow-hidden mb-3">
          <div class="bg-blue-600 dark:bg-blue-500 h-full transition-all duration-1000 ease-out" style="width: ${percent}%"></div>
        </div>
        <p class="text-[11px] opacity-60 flex items-center gap-1">
          <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
          失败自动退还额度 · 短时重复请求不扣费。（10s）
        </p>
      </div>
  
      <div class="section-box">
        <h2 class="text-lg font-bold mb-4 flex items-center gap-2 opacity-90">
          <svg class="w-5 h-5 text-gray-700 dark:text-gray-300" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
          GitHub 文件加速 / 通用链接
        </h2>
        <div class="flex flex-responsive gap-3">
          <input id="github-url" type="text" placeholder="粘贴 https://github.com/... 链接" class="flex-grow p-3.5 rounded-lg text-sm">
          <button onclick="convertGithubUrl()" class="bg-blue-600 hover:bg-blue-700 text-white px-6 py-3.5 rounded-lg transition font-bold text-sm shadow-md whitespace-nowrap flex items-center justify-center gap-1">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
              获取链接
          </button>
        </div>
        
        <div id="github-result-box" class="hidden mt-5">
          <div class="p-4 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-100 dark:border-emerald-800 rounded-lg mb-3">
               <p id="github-result" class="text-emerald-700 dark:text-emerald-400 font-mono text-xs break-all select-all"></p>
          </div>
          <div class="flex gap-3">
              <button onclick="copyGithubUrl()" class="flex-1 bg-gray-100 dark:bg-slate-700 hover:bg-gray-200 dark:hover:bg-slate-600 text-gray-700 dark:text-gray-200 py-2.5 rounded-lg text-xs font-bold transition">复制链接</button>
              <button onclick="openGithubUrl()" class="flex-1 bg-blue-50 dark:bg-blue-900/20 hover:bg-blue-100 dark:hover:bg-blue-900/40 text-blue-600 dark:text-blue-400 py-2.5 rounded-lg text-xs font-bold transition">立即访问</button>
          </div>
        </div>
      </div>
  
      <div class="section-box">
        <h2 class="text-lg font-bold mb-4 flex items-center gap-2 opacity-90">
          <span class="text-xl">🐳</span> Docker 镜像加速
        </h2>
        <div class="flex flex-responsive gap-3">
          <input id="docker-image" type="text" placeholder="如 nginx 或 library/redis" class="flex-grow p-3.5 rounded-lg text-sm">
          <button onclick="convertDockerImage()" class="bg-indigo-600 hover:bg-indigo-700 text-white px-6 py-3.5 rounded-lg transition font-bold text-sm shadow-md whitespace-nowrap flex items-center justify-center gap-1">
               <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8"/></svg>
               获取命令
          </button>
        </div>
        
        <div id="docker-result-box" class="hidden mt-5">
           <div class="p-4 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-100 dark:border-emerald-800 rounded-lg mb-3">
               <p id="docker-result" class="text-emerald-700 dark:text-emerald-400 font-mono text-xs break-all select-all"></p>
          </div>
          <button onclick="copyDockerCommand()" class="w-full bg-gray-100 dark:bg-slate-700 hover:bg-gray-200 dark:hover:bg-slate-600 text-gray-700 dark:text-gray-200 py-2.5 rounded-lg text-xs font-bold transition">一键复制命令</button>
        </div>
      </div>
  
      <div class="section-box">
          <h2 class="text-lg font-bold mb-4 flex items-center gap-2 opacity-90">
              <svg class="w-5 h-5 text-purple-600 dark:text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>
              镜像源配置 (Daemon.json)
          </h2>
          
          <div class="code-area rounded-lg p-4 overflow-x-auto text-sm">
              <p class="text-gray-500 dark:text-gray-500 mb-1"># 1. 编辑配置文件</p>
              <p class="font-mono text-blue-600 dark:text-blue-400 font-bold mb-4">vim /etc/docker/daemon.json</p>
              
              <p class="text-gray-500 dark:text-gray-500 mb-1"># 2. 填入以下内容</p>
              <pre id="daemon-json-content" class="font-mono text-emerald-600 dark:text-emerald-400 mb-4 bg-transparent p-0 border-0"></pre>
              
              <p class="text-gray-500 dark:text-gray-500 mb-1"># 3. 重启 Docker</p>
              <p class="font-mono text-blue-600 dark:text-blue-400 font-bold">sudo systemctl daemon-reload && sudo systemctl restart docker</p>
          </div>
          
          <button onclick="copyDaemonJson()" class="mt-4 px-4 py-2 bg-gray-800 dark:bg-white hover:bg-black dark:hover:bg-gray-200 text-white dark:text-black rounded-lg text-xs font-bold transition shadow-sm flex items-center gap-2">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"/></svg>
              复制配置
          </button>
      </div>
  
      <footer class="mt-12 text-center pb-8">
            <a href="https://github.com/Kevin-YST-Du/Cloudflare-Accel" 
                target="_blank" 
                class="text-[10px] text-blue-600 dark:text-blue-400 uppercase tracking-widest font-bold opacity-80 hover:opacity-100 hover:underline transition-all">
        Powered by Kevin-YST-Du/Cloudflare-Accel
    </a>
</footer>
    </div>
  
    <div id="confirmModal" class="modal-overlay">
      <div class="modal-content">
         <div class="text-center">
            <div class="w-12 h-12 bg-red-100 dark:bg-red-900/30 rounded-full flex items-center justify-center mb-4 mx-auto text-red-500">
               <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
            </div>
            <h3 class="text-lg font-bold mb-2">确认重置额度？</h3>
            <p class="text-sm opacity-70 mb-6 px-4">
                此操作仅限管理员 (IP: ${ip})。重置后不可撤销。
            </p>
            <div class="flex gap-3">
               <button onclick="closeModal()" class="flex-1 px-4 py-2.5 bg-gray-100 hover:bg-gray-200 dark:bg-slate-700 dark:hover:bg-slate-600 rounded-lg text-sm font-bold transition">取消</button>
               <button onclick="confirmReset()" class="flex-1 px-4 py-2.5 bg-red-500 hover:bg-red-600 text-white rounded-lg text-sm font-bold transition shadow-lg shadow-red-500/30">确定重置</button>
            </div>
         </div>
      </div>
    </div>
  
    <div id="toast" class="toast bg-slate-800 text-white"></div>
  
    <script>
      const currentDomain = window.location.hostname;
      const WORKER_PASSWORD = "${password}"; 
      let githubAcceleratedUrl = '';
      let dockerCommand = '';
      
      // JSON Config
      const daemonJsonObj = { "registry-mirrors": ["https://" + currentDomain] };
      const daemonJsonStr = JSON.stringify(daemonJsonObj, null, 2);
      document.getElementById('daemon-json-content').textContent = daemonJsonStr;
  
      // Theme Toggle
      function toggleTheme() {
        const body = document.body;
        const sun = document.querySelector('.sun');
        const moon = document.querySelector('.moon');
        if (body.classList.contains('light-mode')) {
          body.classList.remove('light-mode'); body.classList.add('dark-mode');
          sun.classList.add('hidden'); moon.classList.remove('hidden');
          localStorage.setItem('theme', 'dark');
        } else {
          body.classList.remove('dark-mode'); body.classList.add('light-mode');
          moon.classList.add('hidden'); sun.classList.remove('hidden');
          localStorage.setItem('theme', 'light');
        }
      }
      if (localStorage.getItem('theme') === 'dark') toggleTheme();
  
      // Toast
      function showToast(message, isError = false) {
        const toast = document.getElementById('toast');
        toast.innerHTML = message;
        toast.className = 'toast ' + (isError ? 'bg-red-500' : 'bg-slate-800') + ' show';
        setTimeout(() => toast.classList.remove('show'), 3000);
      }
  
      // Modal
      function openModal() { document.getElementById('confirmModal').classList.add('open'); }
      function closeModal() { document.getElementById('confirmModal').classList.remove('open'); }
  
      // Copy
      function copyToClipboard(text) {
        if (navigator.clipboard && window.isSecureContext) { return navigator.clipboard.writeText(text); }
        const textArea = document.createElement("textarea");
        textArea.value = text; textArea.style.position = "fixed";
        document.body.appendChild(textArea); textArea.focus(); textArea.select();
        try { document.execCommand('copy'); document.body.removeChild(textArea); return Promise.resolve(); } 
        catch (err) { document.body.removeChild(textArea); return Promise.reject(err); }
      }
  
      // Logic
      function convertGithubUrl() {
        let input = document.getElementById('github-url').value.trim();
        if (!input) return showToast('❌ 请输入链接', true);
        if (!input.startsWith('http')) { input = 'https://' + input; }
        githubAcceleratedUrl = window.location.origin + '/' + WORKER_PASSWORD + '/' + input;
        document.getElementById('github-result').textContent = githubAcceleratedUrl;
        document.getElementById('github-result-box').classList.remove('hidden');
        copyToClipboard(githubAcceleratedUrl).then(() => showToast('✅ 已复制到剪贴板'));
      }
      function copyGithubUrl() { copyToClipboard(githubAcceleratedUrl).then(() => showToast('✅ 已复制')); }
      function openGithubUrl() { window.open(githubAcceleratedUrl, '_blank'); }
  
      function convertDockerImage() {
        const input = document.getElementById('docker-image').value.trim();
        if (!input) return showToast('❌ 请输入镜像名', true);
        dockerCommand = 'docker pull ' + currentDomain + '/' + input;
        document.getElementById('docker-result').textContent = dockerCommand;
        document.getElementById('docker-result-box').classList.remove('hidden');
        copyToClipboard(dockerCommand).then(() => showToast('✅ 已复制'));
      }
      function copyDockerCommand() { copyToClipboard(dockerCommand).then(() => showToast('✅ 已复制')); }
      function copyDaemonJson() { copyToClipboard(daemonJsonStr).then(() => showToast('✅ JSON 配置已复制')); }
  
      async function confirmReset() {
        closeModal();
        try {
          const res = await fetch('/' + WORKER_PASSWORD + '/reset');
          const data = await res.json();
          if (res.ok) {
              showToast('✅ 额度已重置');
              setTimeout(() => location.reload(), 800);
          } else {
              showToast('❌ ' + (data.message || '无权操作'), true);
          }
        } catch (e) {
          showToast('❌ 网络错误', true);
        }
      }
    </script>
  </body>
  </html>
  `;
}
