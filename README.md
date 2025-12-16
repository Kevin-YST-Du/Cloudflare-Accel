Cloudflare-Accel Ultimate Edition

[架构概览](#overview) [核心特性](#features) [配置实验室](#config) [效能分析](#impact)

# 全能下载代理与 Docker 镜像加速服务

基于 Cloudflare Workers 的下一代加速方案。智能解决 S3 签名错误，支持断点续传，提供企业级安全防护与可视化管理。

Docker 智能加速

S3 签名修复

文件流式处理

## 智能请求路由架构

工作原理可视化

本部分展示了 Cloudflare-Accel 如何处理复杂的网络请求。不同于普通代理，它采用**递归处理**机制，能自动追踪多级跳转（如 302/307），特别是针对 Docker Layer 存储在 AWS S3 或 R2 时的场景。

系统会自动识别 Docker 客户端（CLI）请求并进行**智能补全**（如自动添加 \`library/\`），同时在遇到预签名 URL 时智能剥离头部，防止 403 签名错误。

#### 核心优势

+   CLI 拉取无需密码（User-Agent 识别）
+   自动修复 S3/R2 签名问题
+   流式传输大文件，内存占用极低

交互式拓扑图：点击节点查看角色

## 全能版 vs 普通代理

为什么选择 Ultimate Edition？我们不仅仅是转发流量，更内置了深度优化的逻辑处理层，解决了普通反向代理无法处理的 Docker 认证挑战和 S3 签名校验问题。

能力维度对比雷达图

### 路径自动补全

自动识别 Docker 官方镜像，将 \`nginx\` 自动转换为 \`library/nginx\`，无需手动输入完整路径。

### 安全防护体系

支持 IP 白名单、国家/地区限制、黑白名单域名过滤，以及 robots.txt 防爬虫。

### 内容智能重写

下载脚本时（如 .sh），自动将内部的 URL 替换为代理链接，实现“一键脚本”的全链路加速。

## 配置实验室

Cloudflare-Accel 推荐使用环境变量进行无代码配置。在下方模拟配置，预览系统行为。

### 环境变量设置

访问密码 (PASSWORD) 

IP 白名单 (ALLOW\_IPS) 

国家限制 (ALLOW\_COUNTRIES) 

黑名单域名 (BLACKLIST) 

开启缓存 (ENABLE\_CACHE) 

DAEMON.JSON PREVIEW

// Docker 客户端拉取示例

$ docker pull docker.example.com/nginx

// 浏览器访问示例 (需密码)

https://docker.example.com/123456/https://github.com/...

// 访问控制状态

公开访问 (受密码保护)

## 稳定性提升分析

S3 签名修复效果

在拉取大型 Docker 镜像（如 AI 镜像）时，Docker Hub 通常会将实际的数据层（Blobs）重定向到 AWS S3 或 Cloudflare R2。如果你直接修改请求头（如添加 Authorization），会导致 S3 预签名 URL 校验失败，返回 **403 Forbidden**。

本系统内置智能识别逻辑，在检测到预签名 URL 时自动剥离干扰头部，显著提升拉取成功率。

403 错误率对比 (模拟数据)

#### 常见报错

`error parsing HTTP 403 response body: invalid character '<' looking for beginning of value...`

#### 优化后

智能剥离 Authorization 头，保留 Host，S3 签名验证通过，实现 100% 兼容。

Powered by Cloudflare Workers

本项目基于 fscarmen2/Cloudflare-Accel 进行二次开发。UI 与核心逻辑深度优化。

© 2025 Cloudflare-Accel Ultimate. MIT License.

// --- 1. Architecture Visualization (Plotly) --- const drawNetworkViz = () => { const nodes = { x: \[0, 1, 2, 2, 2\], y: \[1, 1, 2, 1, 0\], text: \['User (Client)', 'CF Worker', 'Docker Hub', 'GitHub', 'AWS S3 (Blobs)'\], marker: { size: \[30, 40, 25, 25, 25\], color: \['#64748b', '#0ea5e9', '#0284c7', '#333333', '#eab308'\] } }; const edges = \[ { source: 0, target: 1, label: 'Req /v2/' }, { source: 1, target: 2, label: 'Get Manifest' }, { source: 1, target: 3, label: 'Get File' }, { source: 2, target: 1, label: '307 Redirect' }, { source: 1, target: 4, label: 'Recursive Fetch (Fix Sig)' } \]; const traceNodes = { x: nodes.x, y: nodes.y, mode: 'markers+text', type: 'scatter', text: nodes.text, textposition: 'bottom center', marker: { size: nodes.marker.size, color: nodes.marker.color } }; // Drawing simple lines for edges manually for cleaner look const layout = { margin: { t: 20, b: 20, l: 20, r: 20 }, xaxis: { showgrid: false, zeroline: false, showticklabels: false, range: \[-0.5, 2.5\] }, yaxis: { showgrid: false, zeroline: false, showticklabels: false, range: \[-0.5, 2.5\] }, showlegend: false, hovermode: 'closest', paper\_bgcolor: 'rgba(0,0,0,0)', plot\_bgcolor: 'rgba(0,0,0,0)', shapes: edges.map((e, i) => ({ type: 'line', x0: nodes.x\[e.source\], y0: nodes.y\[e.source\], x1: nodes.x\[e.target\], y1: nodes.y\[e.target\], line: { color: '#cbd5e1', width: 2, dash: i > 2 ? 'dot' : 'solid' } })) }; // Add annotations for edge labels const annotations = edges.map((e) => ({ x: (nodes.x\[e.source\] + nodes.x\[e.target\]) / 2, y: (nodes.y\[e.source\] + nodes.y\[e.target\]) / 2, text: e.label, showarrow: false, font: { size: 10, color: '#64748b' }, bgcolor: '#ffffff', borderpad: 2 })); layout.annotations = annotations; Plotly.newPlot('networkViz', \[traceNodes\], layout, {displayModeBar: false, responsive: true}); }; // --- 2. Feature Comparison (Chart.js) --- const drawFeatureRadar = () => { const ctx = document.getElementById('featureRadar').getContext('2d'); new Chart(ctx, { type: 'radar', data: { labels: \['安全性', '易用性', 'Docker 兼容性', '大文件稳定性', '抗封锁能力'\], datasets: \[{ label: 'Cloudflare-Accel (Ultimate)', data: \[95, 90, 100, 98, 95\], fill: true, backgroundColor: 'rgba(14, 165, 233, 0.2)', borderColor: 'rgb(14, 165, 233)', pointBackgroundColor: 'rgb(14, 165, 233)', pointBorderColor: '#fff', pointHoverBackgroundColor: '#fff', pointHoverBorderColor: 'rgb(14, 165, 233)' }, { label: '普通反代脚本', data: \[40, 60, 50, 40, 60\], fill: true, backgroundColor: 'rgba(148, 163, 184, 0.2)', borderColor: 'rgb(148, 163, 184)', pointBackgroundColor: 'rgb(148, 163, 184)', pointBorderColor: '#fff', pointHoverBackgroundColor: '#fff', pointHoverBorderColor: 'rgb(148, 163, 184)' }\] }, options: { responsive: true, maintainAspectRatio: false, scales: { r: { angleLines: { display: false }, suggestedMin: 0, suggestedMax: 100 } } } }); }; // --- 3. Impact Analysis (Chart.js) --- const drawErrorChart = () => { const ctx = document.getElementById('errorChart').getContext('2d'); new Chart(ctx, { type: 'bar', data: { labels: \['普通反代', 'Ultimate Edition'\], datasets: \[{ label: 'Layer 下载成功率 (%)', data: \[45, 99.9\], backgroundColor: \[ 'rgba(239, 68, 68, 0.6)', // Red for low 'rgba(16, 185, 129, 0.6)' // Green for high \], borderColor: \[ 'rgb(239, 68, 68)', 'rgb(16, 185, 129)' \], borderWidth: 1 }\] }, options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true, max: 100 } }, plugins: { legend: { display: false } } } }); }; // --- 4. Config Simulator Logic --- const updateConfigPreview = () => { const pass = document.getElementById('conf\_pass').value; const ips = document.getElementById('conf\_ips').value; const country = document.getElementById('conf\_country').value; const black = document.getElementById('conf\_black').value; document.getElementById('preview\_pass').innerText = pass || '123456'; let statusHtml = '<i class="fa-solid fa-check text-green-500"></i> 公开访问 (受密码保护)'; if (ips || country) { let restrictions = \[\]; if (ips) restrictions.push(\`IP (${ips})\`); if (country) restrictions.push(\`国家 (${country})\`); statusHtml = \`<i class="fa-solid fa-shield-halved text-yellow-500"></i> 受限访问: 仅允许 ${restrictions.join(' 或 ')}\`; } if (black) { statusHtml += \`<br><i class="fa-solid fa-ban text-red-500"></i> 已屏蔽: ${black}\`; } document.getElementById('access\_status').innerHTML = statusHtml; }; // Initialize window.addEventListener('load', () => { drawNetworkViz(); drawFeatureRadar(); drawErrorChart(); // Add event listeners for inputs \['conf\_pass', 'conf\_ips', 'conf\_country', 'conf\_black'\].forEach(id => { document.getElementById(id).addEventListener('input', updateConfigPreview); }); }); 等基本所有的格式，如果有所问题，可在以下方式联系我 -->

# 开发者武器库 - 程序员的专业工具箱

**欢迎访问 [DevTool](https://devtool.tech)**

本工具地址: [Devtool/HTML-To-Markdown](http://devtool.tech/html-md)

**如果需要在 URL 生成 Markdown 后进行某些修改，建议使用本站另一工具：[码途编辑器](https://markdown.devtool.tech/app)，并进行如下操作。**

![](https://static.shanyue.tech/images/23-09-21/clipboard-5477.c45893.webp)

## 联系方式

+   微信: shanyue94(山月)
+   Github: [shfshanyue](https://github.com/shfshanyue)
+   博客: [shanyue.tech](https://shanyue.tech)

## 联系方式: 表格版

| 账号 | 地址 |
| --- | --- |
| 微信 | shanyue94(山月) |
| Github | shfshanyue |
| 博客 | shanyue.tech |
