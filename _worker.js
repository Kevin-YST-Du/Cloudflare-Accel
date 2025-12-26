/**
 * -----------------------------------------------------------------------------------------
 * Cloudflare Worker: 终极 Docker & Linux 代理 (高性能版 v3.5 - 增强 GitHub 仓库识别)
 * -----------------------------------------------------------------------------------------
 * 核心功能：
 * 1. Docker Hub/GHCR 等镜像仓库加速下载。
 * 2. 智能处理 Docker 的 library/ 命名空间补全。
 * 3. Linux 软件源加速，新增对 debian-security 的支持。
 * 4. 集成 KV 存储进行每日 IP 请求限额控制。
 * 5. Web Dashboard (修复了交互 Bug，增强了 Linux 换源脚本的兼容性，新增 Git Clone 智能识别)。
 * -----------------------------------------------------------------------------------------
 */

// ==============================================================================
// 1. 全局配置与常量定义
// ==============================================================================

const DEFAULT_CONFIG = {
    // --- 基础配置 ---
    PASSWORD: "123456",               // 访问密码 (用于 Web 界面和通用代理验证)
    MAX_REDIRECTS: 5,                 // 最大重定向次数 (防止死循环)
    ENABLE_CACHE: true,               // 是否开启 Worker 级缓存
    CACHE_TTL: 3600,                  // 缓存时间 (秒)
    
    // --- 访问控制 (安全) ---
    BLACKLIST: "",                    // 域名黑名单 (逗号分隔)
    WHITELIST: "",                    // 域名白名单 (逗号分隔，如果不为空则只允许白名单)
    ALLOW_IPS: "",                    // 允许访问的客户端 IP (空则允许所有)
    ALLOW_COUNTRIES: "",              // 允许访问的国家代码 (如 CN, US)
    
    // --- 额度限制 (KV) ---
    DAILY_LIMIT_COUNT: 200,           // 每个 IP 每日最大请求次数
    
    // --- 权限管理 ---
    // 管理员 IP (拥有重置额度、查看统计、清空全站数据的权限)
    ADMIN_IPS: `
    127.0.0.1
    `,                    
    
    // 免额度 IP 白名单 (请求不计入每日限额)
    IP_LIMIT_WHITELIST: `
    127.0.0.1
    `, 
};

// 支持的 Docker Registry 上游列表
const DOCKER_REGISTRIES = [
    'docker.io', 'registry-1.docker.io', 'quay.io', 'gcr.io', 
    'k8s.gcr.io', 'registry.k8s.io', 'ghcr.io', 'docker.cloudsmith.io'
];

// Docker 简写映射：将 registry 别名映射到完整的 URL
const REGISTRY_MAP = {
    'ghcr.io': 'https://ghcr.io',
    'quay.io': 'https://quay.io',
    'gcr.io': 'https://gcr.io',
    'k8s.gcr.io': 'https://k8s.gcr.io',
    'registry.k8s.io': 'https://registry.k8s.io',
    'docker.cloudsmith.io': 'https://docker.cloudsmith.io',
    'nvcr.io': 'https://nvcr.io'
};

// [新增] Linux 软件源镜像映射 (修复 Security 源 404 问题，添加 RedHat 系支持)
const LINUX_MIRRORS = {
    'ubuntu': 'http://archive.ubuntu.com/ubuntu',
    'ubuntu-security': 'http://security.ubuntu.com/ubuntu', // Ubuntu 安全源
    'debian': 'http://deb.debian.org/debian',
    'debian-security': 'http://security.debian.org/debian-security', // Debian 安全源
    'centos': 'https://vault.centos.org',
    'centos-stream': 'http://mirror.stream.centos.org',
    'rockylinux': 'https://download.rockylinux.org/pub/rocky', // Rocky Linux (RedHat 替代)
    'almalinux': 'https://repo.almalinux.org/almalinux', // AlmaLinux (RedHat 替代)
    'fedora': 'https://download.fedoraproject.org/pub/fedora/linux', // Fedora
    'alpine': 'http://dl-cdn.alpinelinux.org/alpine',
    'kali': 'http://http.kali.org/kali',
    'archlinux': 'https://geo.mirror.pkgbuild.com'
};

// 网站图标 (闪电 SVG)
const LIGHTNING_SVG = `<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M13 2L3 14H12L11 22L21 10H12L13 2Z" stroke="#F59E0B" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>`;

// ==============================================================================
// 2. Worker 主入口 (Main Handler)
// ==============================================================================

export default {
    async fetch(request, env, ctx) {
        // 辅助函数：解析环境变量中的逗号/换行分隔符为数组
        const parseList = (v, d) => (v || d).split(/[\n,]/).map(s => s.trim()).filter(s => s.length > 0);
        
        // 合并 环境变量(env) 和 默认配置(DEFAULT_CONFIG)
        // 优先使用 Env 变量，方便在 Cloudflare 后台动态调整
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
        
        // --- 2.0 静态资源响应 ---
        if (url.pathname === '/robots.txt') return new Response("User-agent: *\nDisallow: /", { headers: { "Content-Type": "text/plain" } });
        if (url.pathname === '/favicon.ico') return new Response(LIGHTNING_SVG, { headers: { "Content-Type": "image/svg+xml" } });

        // --- 2.1 Token 劫持 (Docker Login/Pull 认证) ---
        // Docker 客户端会先请求 /token 获取 bearer token，这里需要代理该请求以解决跨域和补全问题
        if (url.pathname === '/token') {
            return handleTokenRequest(request, url);
        }

        // --- 2.2 CORS 预检请求 ---
        // 允许浏览器跨域访问
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

        // --- 2.3 安全与地区检查 ---
        if (CONFIG.ALLOW_IPS.length > 0 || CONFIG.ALLOW_COUNTRIES.length > 0) {
            const country = request.cf ? request.cf.country : "XX";
            let allow = false;
            if (CONFIG.ALLOW_IPS.includes(clientIP)) allow = true;
            if (!allow && CONFIG.ALLOW_COUNTRIES.includes(country)) allow = true;
            if (!allow) return new Response(`Access Denied`, { status: 403 });
        }

        // --- 2.4 计费检查 (Rate Limiting) ---
        const isWhitelisted = CONFIG.IP_LIMIT_WHITELIST.includes(clientIP);
        let currentUsage = 0;
        
        // 只有绑定了 KV 且 IP 不在白名单时才检查
        if (!isWhitelisted && env.IP_LIMIT_KV) {
             currentUsage = await getIpUsageCount(clientIP, env);
             if (currentUsage >= CONFIG.DAILY_LIMIT_COUNT) {
                 return new Response(`⚠️ Daily Limit Exceeded: ${currentUsage}/${CONFIG.DAILY_LIMIT_COUNT}`, { status: 429 });
             }
        }

        // 判断是否是 Docker 镜像拉取请求 (用于后续计费判定)
        const isDockerV2 = url.pathname.startsWith("/v2/");
        const isDockerCharge = isDockerV2 
            && (userAgent.includes("docker") || userAgent.includes("go-http") || userAgent.includes("containerd"))
            && (url.pathname.includes("/manifests/") || url.pathname.includes("/blobs/")) // 只针对 manifest 和 blob 计费
            && request.method === "GET";

        let shouldCharge = false;
        if (isDockerCharge && !isWhitelisted) {
            // 优化：使用 Cache API 进行毫秒级去重，防止同一个 manifest 请求短时间内多次触发 KV 写操作
            const isDuplicate = await checkIsDuplicate(clientIP, url.pathname);
            if (!isDuplicate) {
                shouldCharge = true;
                ctx.waitUntil(setDuplicateFlag(clientIP, url.pathname)); // 异步写入去重标记
            }
        }

        // --- 2.5 核心业务路由分发 ---
        let response;
        try {
            if (isDockerV2) {
                // -> 进入 Docker 加速逻辑
                response = await handleDockerRequest(request, url);
            } else {
                // -> 进入 通用代理 / Dashboard 逻辑
                const path = url.pathname;
                // 路径格式: /密码/目标URL
                const match = path.match(/^\/([^/]+)(?:\/(.*))?$/);
                
                // 密码错误或格式不对，返回 404 隐藏入口
                if (!match || match[1] !== CONFIG.PASSWORD) {
                    return new Response("404 Not Found", { status: 404 });
                }

                const subPath = match[2];

                // 2.5.1 管理员命令 API: 重置单 IP
                if (subPath === "reset") {
                    if (!CONFIG.ADMIN_IPS.includes(clientIP)) return new Response("Forbidden", { status: 403 });
                    ctx.waitUntil(resetIpUsage(clientIP, env)); // 异步重置 KV
                    return new Response(JSON.stringify({ status: "success" }), { status: 200 });
                }

                // 2.5.2 管理员命令 API: 清空全站数据 (新增)
                if (subPath === "reset-all") {
                    if (!CONFIG.ADMIN_IPS.includes(clientIP)) return new Response("Forbidden", { status: 403 });
                    ctx.waitUntil(resetAllIpStats(env)); // 调用清空所有函数
                    return new Response(JSON.stringify({ status: "success" }), { status: 200 });
                }

                // 2.5.3 管理员命令 API: 获取统计
                if (subPath === "stats") {
                    if (!CONFIG.ADMIN_IPS.includes(clientIP)) return new Response("Forbidden", { status: 403 });
                    const stats = await getAllIpStats(env);
                    return new Response(JSON.stringify({ status: "success", data: stats }), { status: 200 });
                }

                // 2.5.4 如果没有目标 URL，显示 Dashboard
                if (!subPath) {
                    return new Response(renderDashboard(url.hostname, CONFIG.PASSWORD, clientIP, currentUsage, CONFIG.DAILY_LIMIT_COUNT, CONFIG.ADMIN_IPS), {
                        status: 200, headers: { "Content-Type": "text/html;charset=UTF-8" }
                    });
                }

                // 2.5.5 [新增] Linux 软件源加速路由识别
                // 核心修复：Linux 镜像匹配逻辑
                // 优先匹配最长的前缀，以区分 debian 和 debian-security
                const sortedMirrors = Object.keys(LINUX_MIRRORS).sort((a, b) => b.length - a.length);
                const linuxDistro = sortedMirrors.find(k => subPath.startsWith(k + '/') || subPath === k);

                if (linuxDistro) {
                    // -> 进入 Linux 软件源加速逻辑 (支持 Range/Streaming)
                    const realPath = subPath.replace(linuxDistro, '').replace(/^\//, ''); // 移除前缀
                    const upstreamBase = LINUX_MIRRORS[linuxDistro];
                    response = await handleLinuxMirrorRequest(request, upstreamBase, realPath);
                } else {
                    // 2.5.6 通用文件代理 (如 GitHub 文件加速)
                    response = await handleGeneralProxy(request, subPath + (url.search || ""), CONFIG, ctx);
                }
            }

            // --- 2.6 异步计费执行 ---
            // 关键优化：使用 ctx.waitUntil 将 KV 写操作放入后台，避免阻塞当前请求的响应时间
            if (shouldCharge && response && response.status >= 200 && response.status < 400) {
                ctx.waitUntil(incrementIpUsage(clientIP, env));
            }

            return response;

        } catch (e) {
            return new Response(JSON.stringify({ error: e.message }), { status: 500 });
        }
    }
};

// ==============================================================================
// 3. 辅助功能函数 (Token, Docker, Linux, KV)
// ==============================================================================

// 3.1 鉴权处理逻辑 (Token Handler)
async function handleTokenRequest(request, url) {
    const scope = url.searchParams.get('scope');
    let upstreamAuthUrl = 'https://auth.docker.io/token'; 
    
    // 根据 scope 判断是哪个 registry 的认证请求
    for (const [domain, _] of Object.entries(REGISTRY_MAP)) {
        if (scope && scope.includes(domain)) {
            upstreamAuthUrl = `https://${domain}/token`;
            break;
        }
    }

    const newUrl = new URL(upstreamAuthUrl);
    newUrl.search = url.search;

    // 针对 Docker Hub (auth.docker.io) 的特殊处理
    if (upstreamAuthUrl === 'https://auth.docker.io/token') {
        newUrl.searchParams.set('service', 'registry.docker.io');
        // 自动补全 library/ 
        // 例如: scope=repository:alpine:pull -> scope=repository:library/alpine:pull
        if (scope && scope.startsWith('repository:')) {
            const parts = scope.split(':');
            // 如果只有两部分且没有斜杠 (如 alpine)，且不是其他 known registry
            if (parts.length >= 3 && !parts[1].includes('/') && !Object.keys(REGISTRY_MAP).some(d => parts[1].startsWith(d))) {
                parts[1] = 'library/' + parts[1];
                newUrl.searchParams.set('scope', parts.join(':'));
            }
        }
    }

    // 构造发往上游的请求
    const newHeaders = new Headers(request.headers);
    newHeaders.set('Host', newUrl.hostname);
    // 伪装 User-Agent，防止被上游识别为爬虫
    newHeaders.set('User-Agent', 'Docker-Client/24.0.5 (linux)');
    newHeaders.delete('Cf-Connecting-Ip');
    newHeaders.delete('Cf-Worker');

    return fetch(new Request(newUrl, {
        method: request.method,
        headers: newHeaders,
        redirect: 'follow'
    }));
}

// 3.2 Docker 核心处理逻辑 (Docker V2 Handler)
async function handleDockerRequest(request, url) {
    // 移除路径中的 /v2/ 前缀
    let path = url.pathname.replace(/^\/v2\//, '');
    
    // 默认上游是 Docker Hub
    let targetDomain = 'registry-1.docker.io'; 
    let upstream = 'https://registry-1.docker.io';
    
    // 4.1 Root 路径 (Docker Client 的连通性检查)
    if (path === '' || path === '/') {
        const rootReq = new Request('https://registry-1.docker.io/v2/', { method: 'GET', headers: request.headers });
        const resp = await fetch(rootReq);
        // 如果返回 401，说明需要认证，必须修改 Www-Authenticate 头，将 realm 指回 Worker
        if (resp.status === 401) {
            return rewriteAuthHeader(resp, new URL(request.url).origin);
        }
        return resp;
    }

    // 4.2 路由识别：检查路径第一段是否为 ghcr.io 等其他仓库
    const pathParts = path.split('/');
    if (REGISTRY_MAP[pathParts[0]]) {
        targetDomain = pathParts[0];
        upstream = REGISTRY_MAP[pathParts[0]];
        path = pathParts.slice(1).join('/'); // 移除域名部分，保留剩余路径
    } else if (targetDomain === 'registry-1.docker.io') {
        // 4.3 Docker Hub 智能补全 library/
        // 逻辑：如果第一段不是 API 关键字(manifests/blobs/tags)，也不包含点(.)，且不是 sha256，则认为是官方镜像
        const p0 = pathParts[0];
        if (pathParts.length > 1 && !p0.includes('.') && p0 !== 'manifests' && p0 !== 'blobs' && p0 !== 'tags' && !p0.startsWith('sha256:')) {
            if (p0 !== 'library') {
                 // 进一步确认后续部分是 API 动作
                 if (pathParts[1] === 'manifests' || pathParts[1] === 'blobs' || pathParts[1] === 'tags') {
                     path = 'library/' + path;
                 }
            }
        }
    }

    const targetUrl = `${upstream}/v2/${path}` + url.search;
    const newHeaders = new Headers(request.headers);
    newHeaders.set('Host', targetDomain);
    newHeaders.set('User-Agent', 'Docker-Client/24.0.5 (linux)');
    newHeaders.delete('Cf-Connecting-Ip');
    
    // 4.4 发起请求
    // redirect: 'manual' 是关键，我们需要捕获 302 重定向并手动处理
    const response = await fetch(targetUrl, {
        method: request.method,
        headers: newHeaders,
        body: request.body,
        redirect: 'manual' 
    });

    // 4.5 处理认证挑战 (401 Unauthorized)
    if (response.status === 401) {
        return rewriteAuthHeader(response, new URL(request.url).origin);
    }

    // 4.6 处理重定向 (302 Found)
    // Docker Layer 通常存储在 S3 等对象存储，Registry 会返回 302 跳转地址
    // Worker 需要代替客户端去请求这个 Blob 地址，否则客户端直接访问 S3 可能会慢或被墙
    if ([301, 302, 303, 307, 308].includes(response.status)) {
        const location = response.headers.get('Location');
        if (location) {
            return handleBlobProxy(location, request);
        }
    }

    // 透传响应
    const finalResponse = new Response(response.body, response);
    finalResponse.headers.set('Access-Control-Allow-Origin', '*');
    finalResponse.headers.set('Docker-Distribution-API-Version', 'registry/2.0');
    return finalResponse;
}

function rewriteAuthHeader(response, workerOrigin) {
    const newResp = new Response(response.body, response);
    const auth = response.headers.get('WWW-Authenticate');
    if (auth) {
        newResp.headers.set("Www-Authenticate", auth.replace(/realm="([^"]+)"/, `realm="${workerOrigin}/token"`));
        newResp.headers.set('Access-Control-Allow-Origin', '*');
    }
    return newResp;
}

// 3.3 Docker Blob 代理 (支持 Range)
async function handleBlobProxy(targetUrl, originalRequest) {
    const newHeaders = new Headers();
    newHeaders.set('User-Agent', 'Docker-Client/24.0.5 (linux)');
    // 支持断点续传: 转发 Range 头
    const range = originalRequest.headers.get('Range');
    if (range) newHeaders.set('Range', range);

    // 发起请求，注意这里直接 fetch 会自动处理流式响应
    const upstreamResponse = await fetch(targetUrl, { 
        method: 'GET', 
        headers: newHeaders 
    });
    
    const proxyHeaders = new Headers(upstreamResponse.headers);
    proxyHeaders.set('Access-Control-Allow-Origin', '*');
    
    // 关键修复：删除可能导致 Docker Client 校验失败的头
    proxyHeaders.delete('Content-Encoding'); 
    proxyHeaders.delete('Transfer-Encoding');

    // 返回流式响应，支持 206 Partial Content
    return new Response(upstreamResponse.body, {
        status: upstreamResponse.status,
        headers: proxyHeaders
    });
}

// 3.4 KV 计数与 Cache 工具 (Rate Limiting & Utils)
function getDate() { return new Date(new Date().getTime() + 28800000).toISOString().split('T')[0]; } // UTC+8 日期

// 使用 Cache API 实现短时间内的请求去重 (防抖)
async function checkIsDuplicate(ip, path) {
    const cache = caches.default;
    const key = `http://dedup.local/${ip}${path}`; 
    return !!(await cache.match(key)); 
}

async function setDuplicateFlag(ip, path) {
    const cache = caches.default;
    const key = `http://dedup.local/${ip}${path}`;
    await cache.put(key, new Response("1", { headers: { "Cache-Control": "max-age=5" } }));
}

// KV 读取当前用量
async function getIpUsageCount(ip, env) {
    if (!env.IP_LIMIT_KV) return 0;
    const val = await env.IP_LIMIT_KV.get(`limit:${ip}:${getDate()}`);
    return parseInt(val || "0");
}

// KV 增加用量 (写操作)
async function incrementIpUsage(ip, env) {
    if (!env.IP_LIMIT_KV) return;
    const key = `limit:${ip}:${getDate()}`;
    const val = await env.IP_LIMIT_KV.get(key);
    await env.IP_LIMIT_KV.put(key, (parseInt(val || "0") + 1).toString(), { expirationTtl: 86400 });
}

async function resetIpUsage(ip, env) {
    if (!env.IP_LIMIT_KV) return;
    await env.IP_LIMIT_KV.delete(`limit:${ip}:${getDate()}`);
}

async function resetAllIpStats(env) {
    if (!env.IP_LIMIT_KV) return;
    const list = await env.IP_LIMIT_KV.list({ prefix: `limit:`, limit: 1000 });
    for (const key of list.keys) {
        await env.IP_LIMIT_KV.delete(key.name);
    }
}

async function getAllIpStats(env) {
    if (!env.IP_LIMIT_KV) return { totalRequests: 0, uniqueIps: 0, details: [] };
    const today = getDate();
    let total = 0;
    let details = [];
    const list = await env.IP_LIMIT_KV.list({ prefix: `limit:`, limit: 100 }); 
    for (const key of list.keys) {
        const parts = key.name.split(':');
        if (parts.length === 3 && parts[2] === today) {
            const val = await env.IP_LIMIT_KV.get(key.name);
            const count = parseInt(val || "0");
            total += count;
            details.push({ ip: parts[1], count: count });
        }
    }
    details.sort((a, b) => b.count - a.count);
    return { totalRequests: total, uniqueIps: details.length, details };
}

// 3.5 [新增] Linux 软件源加速逻辑 (Streaming & Range)
async function handleLinuxMirrorRequest(request, upstreamBase, path) {
    // 构造上游 URL (例如: http://archive.ubuntu.com/ubuntu/dists/jammy/Release)
    // 确保 path 开头有 slash
    const targetUrl = upstreamBase.endsWith('/') 
        ? upstreamBase + path 
        : upstreamBase + '/' + path;

    const newHeaders = new Headers(request.headers);
    // 移除 Cloudflare 特有头，防止上游误判
    newHeaders.delete('Cf-Connecting-Ip');
    newHeaders.delete('Cf-Worker');
    newHeaders.delete('Host'); // Let fetch set the host
    
    // [关键功能] 支持 Range 请求 (断点续传/多线程下载)
    // 客户端发来的 Range 头 (如 bytes=0-1023) 会被转发给上游
    const range = request.headers.get('Range');
    if (range) {
        newHeaders.set('Range', range);
        // console.log(`[Linux Proxy] Range Request: ${range} -> ${targetUrl}`);
    }

    try {
        const response = await fetch(targetUrl, {
            method: request.method,
            headers: newHeaders,
            redirect: 'follow' // Linux 源通常允许重定向，我们直接跟随
        });

        // 构造响应头
        const responseHeaders = new Headers(response.headers);
        responseHeaders.set('Access-Control-Allow-Origin', '*');
        
        // 确保 Content-Range, Content-Length, Accept-Ranges 被正确透传
        // Cloudflare Worker 的 fetch 通常会自动处理这些，但显式保留是个好习惯
        if (response.headers.has('Content-Range')) {
            responseHeaders.set('Content-Range', response.headers.get('Content-Range'));
        }
        if (response.headers.has('Accept-Ranges')) {
            responseHeaders.set('Accept-Ranges', response.headers.get('Accept-Ranges'));
        }

        // 返回 Response 对象
        // response.body 是 ReadableStream，这实现了“流式传输”
        // 意味着 Worker 不会缓存整个文件，而是收到一点转发一点，极大降低内存占用并加速大文件下载
        return new Response(response.body, {
            status: response.status, // 200 或 206 (Partial Content)
            headers: responseHeaders
        });

    } catch (e) {
        return new Response(`Linux Mirror Proxy Error: ${e.message}`, { status: 502 });
    }
}

// 3.6 通用代理逻辑 (General Proxy Handler)
async function handleGeneralProxy(request, targetUrlStr, CONFIG, ctx) {
    let currentUrlStr = targetUrlStr;
    // 补全协议头
    if (!currentUrlStr.startsWith("http")) currentUrlStr = 'https://' + currentUrlStr.replace(/^(https?):\/+/, '$1://');

    let redirectCount = 0;
    let finalResponse = null;
    const originalHeaders = new Headers(request.headers);

    try {
        while (redirectCount < CONFIG.MAX_REDIRECTS) {
            let currentTargetUrl;
            try { currentTargetUrl = new URL(currentUrlStr); } catch(e) { return new Response("Invalid URL", {status: 400}); }
            
            const domain = currentTargetUrl.hostname;
            if (CONFIG.BLACKLIST.some(k => domain.includes(k))) return new Response("Blocked", { status: 403 });
            if (CONFIG.WHITELIST.length > 0 && !CONFIG.WHITELIST.some(k => domain.includes(k))) return new Response("Blocked", { status: 403 });

            const newHeaders = new Headers(originalHeaders);
            newHeaders.set("Host", currentTargetUrl.hostname);
            newHeaders.set("Referer", currentTargetUrl.origin + "/"); 
            newHeaders.set("Origin", currentTargetUrl.origin);
            if (!newHeaders.get("User-Agent")) newHeaders.set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
            
            // [修复] 通用代理也应该支持 Range，方便下载 GitHub Releases 等大文件
            const range = request.headers.get('Range');
            if (range) newHeaders.set('Range', range);

            newHeaders.delete("Cf-Worker"); newHeaders.delete("Cf-Ray"); newHeaders.delete("Cookie"); newHeaders.delete("X-Forwarded-For");

            const response = await fetch(currentUrlStr, {
                method: request.method, headers: newHeaders, body: request.body, redirect: "manual"
            });

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
        
        if (contentType.includes("text/html")) return rewriteHtml(finalResponse, proxyBase, currentUrlStr);
        
        const responseHeaders = new Headers(finalResponse.headers);
        responseHeaders.delete("Content-Security-Policy"); 
        responseHeaders.set("Access-Control-Allow-Origin", "*");
        responseHeaders.set("X-Proxy-Cache", "MISS");

        return new Response(finalResponse.body, { status: finalResponse.status, headers: responseHeaders });
    } catch (e) { throw e; }
}

function rewriteHtml(response, proxyBase, targetUrlStr) {
    const rewriter = new HTMLRewriter()
        .on("a", new AttributeRewriter("href", proxyBase, targetUrlStr))
        .on("img", new AttributeRewriter("src", proxyBase, targetUrlStr))
        .on("link", new AttributeRewriter("href", proxyBase, targetUrlStr))
        .on("script", new AttributeRewriter("src", proxyBase, targetUrlStr))
        .on("form", new AttributeRewriter("action", proxyBase, targetUrlStr));
    const newHeaders = new Headers(response.headers);
    newHeaders.delete("Content-Security-Policy"); newHeaders.set("Access-Control-Allow-Origin", "*");
    return new Response(rewriter.transform(response).body, { status: response.status, headers: newHeaders });
}

class AttributeRewriter {
    constructor(attr, base, target) { this.attr = attr; this.base = base; this.target = target; }
    element(el) {
        const val = el.getAttribute(this.attr);
        if (val && !val.startsWith("mailto:") && !val.startsWith("#") && !val.startsWith("javascript:")) {
            try { el.setAttribute(this.attr, this.base + new URL(val, this.target).href); } catch (e) {}
        }
    }
}

// ==============================================================================
// 4. Dashboard 渲染 (已优化模态框 UI)
// ==============================================================================

function renderDashboard(hostname, password, ip, count, limit, adminIps) {
    const percent = Math.min(Math.round((count / limit) * 100), 100);
    const isAdmin = adminIps.includes(ip);
    const linuxMirrorsJson = JSON.stringify(Object.keys(LINUX_MIRRORS));

    return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Cloudflare 加速通道</title>
    <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,${encodeURIComponent(LIGHTNING_SVG)}">
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
      /* --- CSS 样式 --- */
      /* ==================== 全局设置 ==================== */
      body { 
          min-height: 100vh; 
          display: flex; 
          align-items: center; 
          justify-content: center; 
          font-family: 'Inter', sans-serif; 
          transition: background-color 0.3s ease; 
          padding: 1rem; 
          margin: 0; 
      }

      /* ==================== 亮色模式 (Light Mode) ==================== */
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
      .light-mode input, .light-mode select { 
          background: white; 
          border: 1px solid #d1d5db; 
          color: #1f293b; 
      }
      .light-mode .code-area { 
          background: #f1f5f9; 
          border: 1px solid #e2e8f0; 
          color: #334155; 
      }
      .light-mode .reset-btn { 
          background: #fee2e2; 
          color: #ef4444; 
          border: 1px solid #fca5a5; 
      }

      /* ==================== 暗黑模式 (Dark Mode) ==================== */
      .dark-mode { 
          background-color: #0f172a; 
          color: #e2e8f0; 
      }
      .dark-mode .custom-content-wrapper { 
          background: transparent; 
          border: none; 
          box-shadow: none; 
      }
      .dark-mode .section-box { 
          background-color: #1e293b; 
          border: 1px solid #334155; 
          box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2); 
      }
      .dark-mode input, .dark-mode select { 
          background-color: #0f172a; 
          border: 1px solid #3b82f6; 
          color: #f1f5f9; 
      }
      .dark-mode input::placeholder { 
          color: #64748b; 
      }
      .dark-mode .code-area { 
          background-color: #020617; 
          border: 1px solid #1e293b; 
          color: #e2e8f0; 
      }
      .dark-mode .reset-btn { 
          background-color: white; 
          color: #ef4444; 
          border: none; 
          box-shadow: 0 2px 4px rgba(0,0,0,0.1); 
      }
      .dark-mode .reset-btn:hover { 
          background-color: #f1f5f9; 
      }

      /* ==================== 通用组件 ==================== */
      .code-area, pre, .select-all { 
          user-select: text !important; 
          -webkit-user-select: text !important; 
      }
      .custom-content-wrapper { 
          width: 80% !important; 
          max-width: 1200px !important; 
          min-width: 320px; 
          margin: auto; 
          padding: 1rem; 
          border-radius: 1.5rem; 
      }
      
      @media (max-width: 768px) { 
          .custom-content-wrapper { 
              width: 100% !important; 
              padding: 0.5rem; 
          } 
          .section-box { 
              padding: 1.25rem !important; 
          } 
          .flex-responsive { 
              flex-direction: column !important; 
              gap: 0.75rem !important; 
          } 
          .flex-responsive button { 
              width: 100% !important; 
          } 
      }

      .section-box { 
          border-radius: 1rem; 
          padding: 2rem; 
          margin-bottom: 1.5rem; 
          transition: all 0.2s; 
          position: relative;
          z-index: 1;
      }

      /* ==================== 顶部导航 ==================== */
      .top-nav { 
          position: fixed; 
          top: 1.5rem; 
          right: 1.5rem; 
          z-index: 50; 
          display: flex; 
          gap: 0.75rem; 
      }
      .nav-btn { 
          width: 2.5rem; 
          height: 2.5rem; 
          border-radius: 9999px; 
          background: rgba(255,255,255,0.5); 
          backdrop-filter: blur(4px); 
          border: 1px solid rgba(0,0,0,0.05); 
          display: flex; 
          align-items: center; 
          justify-content: center; 
          cursor: pointer; 
          transition: all 0.2s; 
          color: #64748b; 
      }
      .nav-btn:hover { 
          transform: scale(1.1); 
          background: white; 
          box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); 
      }
      .dark-mode .nav-btn { 
          background: rgba(255,255,255,0.1); 
          border: 1px solid rgba(255,255,255,0.1); 
          color: #e2e8f0; 
      }
      .dark-mode .nav-btn:hover { 
          background: rgba(255,255,255,0.2); 
      }

      /* ==================== Toast & Input ==================== */
      .toast { 
          position: fixed; 
          bottom: 3rem; 
          left: 50%; 
          transform: translateX(-50%) translateY(20px); 
          padding: 0.75rem 1.5rem; 
          border-radius: 0.5rem; 
          z-index: 100; 
          color: white; 
          opacity: 0; 
          transition: all 0.3s; 
          pointer-events: none; 
          font-weight: 500; 
          font-size: 0.9rem; 
          box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3); 
          display: flex; 
          align-items: center; 
          gap: 0.5rem; 
      }
      .toast.show { 
          opacity: 1; 
          transform: translateX(-50%) translateY(0); 
      }
      input, select { 
          outline: none; 
          transition: all 0.2s; 
      }
      input:focus, select:focus { 
          ring: 2px #3b82f6; 
          ring-offset-2px; 
      }
      .dark-mode input:focus, .dark-mode select:focus { 
          ring: 0; 
          border-color: #60a5fa; 
          box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.3); 
      }

      /* ==================== Modal (模态框) ==================== */
      .modal-overlay { 
          position: fixed; 
          inset: 0; 
          z-index: 999; 
          background: rgba(0, 0, 0, 0.6); 
          backdrop-filter: blur(4px); 
          display: flex; 
          align-items: center; 
          justify-content: center; 
          opacity: 0; 
          pointer-events: none; 
          transition: opacity 0.2s; 
      }
      .modal-overlay.open { 
          opacity: 1; 
          pointer-events: auto; 
      }
      .modal-content { 
          background: white; 
          width: 95%; 
          max-width: 400px; 
          padding: 2rem; 
          border-radius: 1.25rem; 
          box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25); 
          transform: scale(0.9); 
          transition: transform 0.2s; 
      }
      .modal-overlay.open .modal-content { 
          transform: scale(1); 
      }
      .dark-mode .modal-content { 
          background: #1e293b; 
          border: 1px solid #334155; 
          color: #f1f5f9; 
      }
    </style>
</head>
<body class="light-mode">
    <div class="top-nav">
       <a href="https://github.com/Kevin-YST-Du/Cloudflare-Accel" target="_blank" class="nav-btn" aria-label="GitHub Repository">
         <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 24 24"><path fill-rule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" clip-rule="evenodd"></path></svg>
       </a>
       <button onclick="toggleTheme()" class="nav-btn" aria-label="Toggle Theme">
         <span class="sun text-lg">☀️</span><span class="moon hidden text-lg">🌙</span>
       </button>
    </div>
    
    <div class="custom-content-wrapper">
      <h1 class="text-3xl md:text-4xl font-extrabold text-center mb-8 tracking-tight">
        <span class="bg-clip-text text-transparent bg-gradient-to-r from-blue-600 to-indigo-600 dark:from-blue-400 dark:to-indigo-400">Cloudflare 加速通道</span>
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
              <div class="flex gap-2">
                <button onclick="openModal('confirmModal')" class="reset-btn px-3 py-1.5 rounded-lg text-xs font-bold transition-transform hover:scale-105 flex items-center gap-1.5 shadow-sm">
                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                    <span>重置额度</span>
                </button>
                ${isAdmin ? `
                <button onclick="viewAllStats()" class="px-3 py-1.5 rounded-lg text-xs font-bold bg-blue-100 text-blue-600 border border-blue-200 hover:bg-blue-200 transition-transform hover:scale-105 flex items-center gap-1.5 shadow-sm">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"></path></svg>
                    <span>全站统计</span>
                </button>
                ` : ''}
              </div>
          </div>
        </div>
        
        <div class="w-full bg-gray-200 dark:bg-slate-700 rounded-full h-2.5 overflow-hidden mb-3">
          <div class="bg-blue-600 dark:bg-blue-500 h-full transition-all duration-1000 ease-out" style="width: ${percent}%"></div>
        </div>
        <p class="text-[11px] opacity-60 flex items-center gap-1">
          <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
          失败自动退还额度 · 短时重复请求不扣费。（10s）
        </p>

        <div id="stats-panel" class="hidden mt-4 p-4 rounded-xl bg-gray-50 dark:bg-slate-800/50 border border-gray-200 dark:border-slate-700">
            <div class="flex justify-between items-center mb-2">
                <h4 class="text-xs font-bold opacity-70 uppercase tracking-wider">今日全站概况</h4>
                ${isAdmin ? `
                <button onclick="openModal('confirmResetAllModal')" class="text-[10px] text-red-500 hover:text-red-700 font-bold border border-red-200 hover:border-red-400 bg-red-50 hover:bg-red-100 px-2 py-0.5 rounded transition">
                清空全站数据
                </button>
                ` : ''}
            </div>
            
            <div class="mb-2 text-xs font-mono text-blue-600 dark:text-blue-400 border-b border-gray-200 dark:border-slate-700 pb-2">
                 <span id="stats-summary">正在加载...</span>
            </div>

            <div id="stats-list" class="max-h-40 overflow-y-auto text-[10px] font-mono divide-y divide-gray-100 dark:divide-slate-700 pr-2">
            </div>
        </div>
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
              <button id="btn-copy-github" onclick="copyGithubUrl()" class="flex-1 bg-gray-100 dark:bg-slate-700 hover:bg-gray-200 dark:hover:bg-slate-600 text-gray-700 dark:text-gray-200 py-2.5 rounded-lg text-xs font-bold transition">复制链接</button>
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
          <span class="text-xl">🐧</span> Linux 软件源加速 (Range 支持)
        </h2>
        <div class="flex flex-responsive gap-3">
          <select id="linux-distro" class="flex-none p-3.5 rounded-lg text-sm bg-gray-50 dark:bg-slate-800 border-r-8 border-transparent outline-none">
             </select>
          <button onclick="generateLinuxCommand()" class="bg-orange-600 hover:bg-orange-700 text-white px-6 py-3.5 rounded-lg transition font-bold text-sm shadow-md whitespace-nowrap flex items-center justify-center gap-1 w-full md:w-auto">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
              生成换源命令
          </button>
        </div>
        <div id="linux-result-box" class="hidden mt-5">
            <p class="text-xs opacity-70 mb-2">使用以下命令一键替换：</p>
            <div class="p-4 bg-orange-50 dark:bg-orange-900/20 border border-orange-100 dark:border-orange-800 rounded-lg mb-3">
                <p id="linux-result" class="text-orange-700 dark:text-orange-400 font-mono text-xs break-all select-all"></p>
            </div>
            <p class="text-[10px] opacity-60 mt-2 mb-2">
                * 注意：脚本仅替换官方默认源。若您已使用其他镜像源（如阿里云），请手动编辑文件。
            </p>
            <button onclick="copyLinuxCommand()" class="w-full bg-gray-100 dark:bg-slate-700 hover:bg-gray-200 dark:hover:bg-slate-600 text-gray-700 dark:text-gray-200 py-2.5 rounded-lg text-xs font-bold transition">复制命令</button>
        </div>
      </div>
  
      <div class="section-box">
          <h2 class="text-lg font-bold mb-4 flex items-center gap-2 opacity-90">
              <svg class="w-5 h-5 text-purple-600 dark:text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>
              镜像源配置 (Daemon.json)
          </h2>
          <div class="code-area rounded-lg p-4 overflow-x-auto text-sm">
              <p class="text-gray-500 dark:text-gray-500 mb-1"># 1. 编辑配置文件</p>
              <p class="font-mono text-blue-600 dark:text-blue-400 font-bold mb-4">nano /etc/docker/daemon.json</p>
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
            <a href="https://github.com/Kevin-YST-Du/Cloudflare-Accel" target="_blank" class="text-[10px] text-blue-600 dark:text-blue-400 uppercase tracking-widest font-bold opacity-80 hover:opacity-100 hover:underline transition-all">Powered by Kevin-YST-Du/Cloudflare-Accel</a>
      </footer>
    </div>
  
    <div id="confirmModal" class="modal-overlay">
      <div class="modal-content">
         <div class="text-center">
            <div class="w-12 h-12 bg-blue-100 dark:bg-blue-900/30 rounded-full flex items-center justify-center mb-4 mx-auto text-blue-500">
               <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
            </div>
            <h3 class="text-lg font-bold mb-2">确认重置额度？</h3>
            <p class="text-sm opacity-70 mb-6 px-4">此操作将清空您当前 IP (${ip}) 在今日的请求记录记录。</p>
            <div class="flex gap-3">
               <button onclick="closeModal('confirmModal')" class="flex-1 px-4 py-2.5 bg-gray-100 hover:bg-gray-200 dark:bg-slate-700 dark:hover:bg-slate-600 rounded-lg text-sm font-bold transition">取消</button>
               <button onclick="confirmReset()" class="flex-1 px-4 py-2.5 bg-red-500 hover:bg-red-600 text-white rounded-lg text-sm font-bold transition shadow-lg shadow-red-500/30">确定重置</button>
            </div>
         </div>
      </div>
    </div>

    <div id="confirmResetAllModal" class="modal-overlay">
      <div class="modal-content">
         <div class="text-center">
            <div class="w-12 h-12 bg-red-100 dark:bg-red-900/30 rounded-full flex items-center justify-center mb-4 mx-auto text-red-500">
               <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
            </div>
            <h3 class="text-2xl font-bold mb-2">⚠️ 高能预警</h3>
            <p class="text-1xl opacity-70 mb-2 px-4">确定要清空【所有用户】的统计数据吗？</p>
            <p class="text-1xl text-red-500 font-bold mb-6">此操作不可恢复！</p>
            <div class="flex gap-3">
               <button onclick="closeResetAllModal()" class="flex-1 px-4 py-2.5 bg-gray-100 hover:bg-gray-200 dark:bg-slate-700 dark:hover:bg-slate-600 rounded-lg text-sm font-bold transition">取消</button>
               <button onclick="confirmResetAll()" class="flex-1 px-4 py-2.5 bg-red-600 hover:bg-red-700 text-white rounded-lg text-sm font-bold transition shadow-lg shadow-red-600/30">确认清空</button>
            </div>
         </div>
      </div>
    </div>

    <div id="toast" class="toast bg-slate-800 text-white"></div>
    <div id="confirmResetAllModal" class="modal-overlay">
    <div class="modal-content">
       <div class="text-center">
          <div class="w-12 h-12 bg-red-100 dark:bg-red-900/30 rounded-full flex items-center justify-center mb-4 mx-auto text-red-500">
             <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
          </div>
          <h3 class="text-lg font-bold mb-2">⚠️ 高能预警</h3>
          <p class="text-sm opacity-70 mb-2 px-4">确定要清空【所有用户】的统计数据吗？</p>
          <p class="text-xs text-red-500 font-bold mb-6">此操作不可恢复！</p>
          <div class="flex gap-3">
             <button onclick="closeResetAllModal()" class="flex-1 px-4 py-2.5 bg-gray-100 hover:bg-gray-200 dark:bg-slate-700 dark:hover:bg-slate-600 rounded-lg text-sm font-bold transition">取消</button>
             <button onclick="confirmResetAll()" class="flex-1 px-4 py-2.5 bg-red-600 hover:bg-red-700 text-white rounded-lg text-sm font-bold transition shadow-lg shadow-red-600/30">确认清空</button>
          </div>
       </div>
    </div>
  </div>

    <script>
      try {
          window.CURRENT_DOMAIN = window.location.hostname;
          window.WORKER_PASSWORD = "${password}"; 
          window.CURRENT_CLIENT_IP = "${ip}";
          window.LINUX_MIRRORS = ${linuxMirrorsJson};
          
          let githubAcceleratedUrl = '';
          let githubOpenUrl = '';
          let dockerCommand = '';
          let linuxCommand = '';
          
          const linuxSelect = document.getElementById('linux-distro');
          if (linuxSelect) {
              const mainMirrors = window.LINUX_MIRRORS.filter(m => !m.includes('-security'));
              mainMirrors.forEach(distro => {
                  const opt = document.createElement('option');
                  opt.value = distro;
                  opt.textContent = distro.charAt(0).toUpperCase() + distro.slice(1);
                  linuxSelect.appendChild(opt);
              });
          }
          
          const daemonJsonObj = { "registry-mirrors": ["https://" + window.CURRENT_DOMAIN] };
          const daemonJsonStr = JSON.stringify(daemonJsonObj, null, 2);
          const daemonEl = document.getElementById('daemon-json-content');
          if (daemonEl) daemonEl.textContent = daemonJsonStr;
  
          window.toggleTheme = function() {
            try {
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
            } catch(e) { console.error('Theme toggle error:', e); }
          }
          
          try { if (localStorage.getItem('theme') === 'dark') window.toggleTheme(); } catch(e) {}
  
          window.showToast = function(message, isError = false) {
            const toast = document.getElementById('toast');
            toast.innerHTML = message;
            toast.className = 'toast ' + (isError ? 'bg-red-500' : 'bg-slate-800') + ' show';
            setTimeout(() => toast.classList.remove('show'), 3000);
          }
  
          window.openModal = function(id) { document.getElementById(id).classList.add('open'); }
          window.closeModal = function(id) { document.getElementById(id).classList.remove('open'); }
  
          window.copyToClipboard = function(text) {
            if (navigator.clipboard && window.isSecureContext) { return navigator.clipboard.writeText(text); }
            const textArea = document.createElement("textarea");
            textArea.value = text; textArea.style.position = "fixed";
            document.body.appendChild(textArea); textArea.focus(); textArea.select();
            try { document.execCommand('copy'); document.body.removeChild(textArea); return Promise.resolve(); } 
            catch (err) { document.body.removeChild(textArea); return Promise.reject(err); }
          }
  
          window.convertGithubUrl = function() {
            let input = document.getElementById('github-url').value.trim();
            if (!input) return window.showToast('❌ 请输入链接', true);
            if (!input.startsWith('http')) { input = 'https://' + input; }
            
            const prefix = window.location.origin + '/' + window.WORKER_PASSWORD + '/';
            const copyBtn = document.getElementById('btn-copy-github');
            
            const repoRegex = /^https?:\\/\\/(?:www\\.)?github\\.com\\/[^/]+\\/[^/]+(?:\\.git)?\\/?$/;
            
            if (input.endsWith('.git') || repoRegex.test(input)) {
                const accUrl = prefix + input;
                const gitCmd = 'git clone ' + accUrl;
                
                document.getElementById('github-result').innerHTML = 
                    '<span class="block mb-1 font-bold text-indigo-600">终端拉取命令:</span>' + gitCmd + 
                    '<br><br><span class="block mb-1 font-bold text-indigo-600">加速链接:</span>' + accUrl;
                
                githubAcceleratedUrl = gitCmd; 
                githubOpenUrl = accUrl;        
                copyBtn.textContent = '复制命令';
                window.showToast('✅ 已识别为仓库');
            } else {
                githubAcceleratedUrl = prefix + input;
                githubOpenUrl = githubAcceleratedUrl;
                document.getElementById('github-result').textContent = githubAcceleratedUrl;
                copyBtn.textContent = '复制链接';
                window.copyToClipboard(githubAcceleratedUrl).then(() => window.showToast('✅ 已复制到剪贴板'));
            }
            
            document.getElementById('github-result-box').classList.remove('hidden');
          }
          
          window.copyGithubUrl = function() { window.copyToClipboard(githubAcceleratedUrl).then(() => window.showToast('✅ 已复制')); }
          window.openGithubUrl = function() { window.open(githubOpenUrl, '_blank'); }
  
          window.convertDockerImage = function() {
            const input = document.getElementById('docker-image').value.trim();
            if (!input) return window.showToast('❌ 请输入镜像名', true);
            dockerCommand = 'docker pull ' + window.CURRENT_DOMAIN + '/' + input;
            document.getElementById('docker-result').textContent = dockerCommand;
            document.getElementById('docker-result-box').classList.remove('hidden');
            window.copyToClipboard(dockerCommand).then(() => window.showToast('✅ 已复制'));
          }
          window.copyDockerCommand = function() { window.copyToClipboard(dockerCommand).then(() => window.showToast('✅ 已复制')); }
          
          window.generateLinuxCommand = function() {
              const distro = document.getElementById('linux-distro').value;
              const baseUrl = window.location.origin + '/' + window.WORKER_PASSWORD + '/' + distro + '/';
              const securityUrl = window.location.origin + '/' + window.WORKER_PASSWORD + '/' + distro + '-security/';
              
              if (distro === 'ubuntu') {
                  linuxCommand = 'sudo sed -i "s|http://archive.ubuntu.com/ubuntu/|' + baseUrl + '|g" /etc/apt/sources.list && ' +
                                 'sudo sed -i "s|https://archive.ubuntu.com/ubuntu/|' + baseUrl + '|g" /etc/apt/sources.list && ' +
                                 'sudo sed -i "s|http://security.ubuntu.com/ubuntu/|' + securityUrl + '|g" /etc/apt/sources.list && ' +
                                 'sudo sed -i "s|https://security.ubuntu.com/ubuntu/|' + securityUrl + '|g" /etc/apt/sources.list';
              } else if (distro === 'debian') {
                  linuxCommand = 'sudo sed -i "s|http://deb.debian.org/debian|' + baseUrl + '|g" /etc/apt/sources.list && ' +
                                 'sudo sed -i "s|https://deb.debian.org/debian|' + baseUrl + '|g" /etc/apt/sources.list && ' +
                                 'sudo sed -i "s|http://security.debian.org/debian-security|' + securityUrl + '|g" /etc/apt/sources.list && ' +
                                 'sudo sed -i "s|https://security.debian.org/debian-security|' + securityUrl + '|g" /etc/apt/sources.list';
              } else if (distro === 'centos') {
                  linuxCommand = 'sudo sed -i "s/mirrorlist/#mirrorlist/g" /etc/yum.repos.d/*.repo && ' +
                                 'sudo sed -i "s|#baseurl=http://mirror.centos.org|baseurl=' + baseUrl + '|g" /etc/yum.repos.d/*.repo && ' +
                                 'sudo sed -i "s|baseurl=http://mirror.centos.org|baseurl=' + baseUrl + '|g" /etc/yum.repos.d/*.repo';
              } else if (distro === 'rockylinux') {
                  linuxCommand = 'sudo sed -i "s/mirrorlist/#mirrorlist/g" /etc/yum.repos.d/rocky*.repo && ' +
                                 'sudo sed -i "s|#baseurl=http://dl.rockylinux.org/$contentdir|baseurl=' + baseUrl + '|g" /etc/yum.repos.d/rocky*.repo && ' +
                                 'sudo sed -i "s|baseurl=http://dl.rockylinux.org/$contentdir|baseurl=' + baseUrl + '|g" /etc/yum.repos.d/rocky*.repo';
              } else if (distro === 'almalinux') {
                  linuxCommand = 'sudo sed -i "s/mirrorlist/#mirrorlist/g" /etc/yum.repos.d/almalinux*.repo && ' +
                                 'sudo sed -i "s|#baseurl=https://repo.almalinux.org/almalinux|baseurl=' + baseUrl + '|g" /etc/yum.repos.d/almalinux*.repo && ' +
                                 'sudo sed -i "s|baseurl=https://repo.almalinux.org/almalinux|baseurl=' + baseUrl + '|g" /etc/yum.repos.d/almalinux*.repo';
              } else if (distro === 'fedora') {
                  linuxCommand = 'sudo sed -i "s/metalink/#metalink/g" /etc/yum.repos.d/fedora*.repo && ' +
                                 'sudo sed -i "s|#baseurl=http://download.example/pub/fedora/linux|baseurl=' + baseUrl + '|g" /etc/yum.repos.d/fedora*.repo && ' +
                                 'sudo sed -i "s|baseurl=http://download.example/pub/fedora/linux|baseurl=' + baseUrl + '|g" /etc/yum.repos.d/fedora*.repo';
              } else if (distro === 'alpine') {
                  linuxCommand = 'sudo sed -i "s|http://dl-cdn.alpinelinux.org/alpine|' + baseUrl + '|g" /etc/apk/repositories && ' +
                                 'sudo sed -i "s|https://dl-cdn.alpinelinux.org/alpine|' + baseUrl + '|g" /etc/apk/repositories';
              } else {
                  linuxCommand = '# 基础 URL:\\n' + baseUrl;
              }
              
              document.getElementById('linux-result').textContent = linuxCommand;
              document.getElementById('linux-result-box').classList.remove('hidden');
              window.copyToClipboard(linuxCommand).then(() => window.showToast('✅ 已复制换源命令'));
          }
          window.copyLinuxCommand = function() { window.copyToClipboard(linuxCommand).then(() => window.showToast('✅ 已复制')); }

          window.copyDaemonJson = function() { window.copyToClipboard(daemonJsonStr).then(() => window.showToast('✅ JSON 配置已复制')); }
  
          window.confirmReset = async function() {
            window.closeModal('confirmModal');
            try {
              const res = await fetch('/' + window.WORKER_PASSWORD + '/reset');
              const data = await res.json();
              if (res.ok) { window.showToast('✅ 额度已重置'); setTimeout(() => location.reload(), 800); } 
              else { window.showToast('❌ ' + (data.message || '无权操作'), true); }
            } catch (e) { window.showToast('❌ 网络错误', true); }
          }

            // 新增：打开/关闭全站重置弹窗的函数
          window.openResetAllModal = function() { document.getElementById('confirmResetAllModal').classList.add('open'); }
          window.closeResetAllModal = function() { document.getElementById('confirmResetAllModal').classList.remove('open'); }

          // 修改：执行逻辑（移除原生 confirm，改为关闭弹窗后执行）
          window.confirmResetAll = async function() {
            window.closeResetAllModal(); // 先关闭弹窗
            try {
              const res = await fetch('/' + window.WORKER_PASSWORD + '/reset-all');
              if (res.ok) { window.showToast('✅ 全站数据已清空'); window.viewAllStats(); setTimeout(() => location.reload(), 1000); } 
              else { window.showToast('❌ 操作失败', true); }
            } catch (e) { window.showToast('❌ 网络错误', true); }
          }

          window.viewAllStats = async function() {
                const panel = document.getElementById('stats-panel');
                panel.classList.toggle('hidden');
                if (panel.classList.contains('hidden')) return;
                try {
                    if (panel.innerHTML.includes('正在加载...')) window.showToast('正在获取全站数据...');
                    const res = await fetch('/' + window.WORKER_PASSWORD + '/stats');
                    const result = await res.json();
                    if (res.ok && result.status === "success") {
                        const { totalRequests, uniqueIps, details } = result.data;
                        document.getElementById('stats-summary').textContent = '总请求: ' + totalRequests + ' | 活跃IP: ' + uniqueIps;
                        const listContainer = document.getElementById('stats-list');
                        let html = '';
                        if (details && details.length > 0) {
                            for (let i = 0; i < details.length; i++) {
                                const item = details[i];
                                const isMe = item.ip === window.CURRENT_CLIENT_IP;
                                const ipClass = isMe ? 'text-blue-500 font-bold' : 'opacity-70';
                                html += '<div class="flex justify-between py-1.5 hover:bg-gray-100 dark:hover:bg-slate-700/50 px-2 rounded cursor-default">';
                                html +=   '<span class="' + ipClass + '">' + item.ip + '</span>';
                                html +=   '<span class="font-bold">' + item.count + ' 次</span>';
                                html += '</div>';
                            }
                        } else { html = '<div class="text-center py-2 opacity-50">暂无数据</div>'; }
                        listContainer.innerHTML = html;
                    } else { window.showToast('❌ 获取失败', true); }
                } catch (e) { console.error(e); window.showToast('❌ 网络错误', true); }
            }
      } catch(err) { console.error("Dashboard Script Error:", err); }
    </script>
</body>
</html>
  `;
}
