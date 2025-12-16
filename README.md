# Cloudflare-Accel (Ultimate Edition)

基于 Cloudflare Workers 的全能下载代理与 Docker 镜像加速服务。

这是一个集成了 **Docker 镜像智能加速**、**通用文件/网页代理**、**大文件流式处理** 以及 **安全防护** 于一体的终极解决方案。它解决了 Docker 拉取 AWS S3/Cloudflare R2 资源时的 403 签名错误，支持断点续传，并提供了直观的 Web 管理界面。

## 🚀 核心特点

### 1. 🐳 Docker 镜像加速 (核心增强)
- **智能路由**: 自动识别 Docker 客户端请求（User-Agent 检测），**CLI 拉取无需密码**。
- **路径补全**: 自动为 Docker Hub 官方镜像补全 `library/` 前缀（如 `docker pull domain/nginx` 自动转换为 `library/nginx`）。
- **S3 签名修复**: 智能识别并修复 Docker Layer 在重定向到 AWS S3/R2 时的签名问题，彻底解决 `403 Forbidden` 错误。
- **递归处理**: 自动追踪多级 302/307 跳转，确保镜像拉取成功率。
- **多仓库支持**: 完美支持 `docker.io`, `ghcr.io`, `quay.io`, `k8s.gcr.io` 等主流仓库。

### 2. ⚡ 通用文件/网页代理
- **密码保护**: 普通文件下载或网页访问需通过 `/密码/` 路径验证，防止恶意盗用。
- **流式处理**: 支持无限大小的大文件流式传输，内存占用极低。
- **内容重写**:
    - 自动替换 `.sh/.py` 脚本中的 URL 为代理链接。
    - 自动重写网页 HTML 中的 `href`/`src` 链接。
- **防盗链伪装**: 自动修改 Referer/Origin/User-Agent，绕过目标网站限制。

### 3. 🛡️ 安全与隐私
- **隐身模式**: 访问根目录或错误密码返回 404，只有知道密码才能看到管理面板。
- **访问控制**: 支持 **IP 白名单** 和 **国家/地区限制**。
- **黑白名单**: 可配置目标域名的黑名单或白名单。
- **隐私保护**: 内置 `robots.txt` 禁止搜索引擎爬虫收录。

### 4. 🎨 现代化 UI
- **经典双栏设计**: 上方通用加速（带打开链接），下方 Docker 加速（带复制命令）。
- **配置生成器**: UI 底部一键生成 `daemon.json` 配置内容。
- **自动适配**: 支持深色/浅色模式切换。

---

## 🛠️ 部署方法

### 1. 部署代码
#### 1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/)。
#### 2. 进入 **Workers & Pages** -> **Create Application** -> **Create Worker**。
#### 3. 命名你的 Worker（例如 `docker-accel`），点击 **Deploy**。
#### 4. 点击 **Edit code**，将本项目提供的 `worker.js` 代码全选粘贴覆盖，**Save and Deploy**。

### 2. 配置环境变量 (推荐)
为了安全和灵活性，建议在 Cloudflare 后台设置配置，而不是修改代码。
进入 Worker 的 **Settings** -> **Variables**，添加以下变量：

| 变量名 | 说明 | 示例值 |
| :--- | :--- | :--- |
| `PASSWORD` | **[必填]** 访问密码 (用于 Web 界面和普通代理) | `123456` |
| `ALLOW_IPS` | 允许访问的客户端 IP (逗号分隔，留空不限制) | `1.2.3.4, 223.5.5.5` |
| `ALLOW_COUNTRIES` | 允许访问的国家代码 (逗号分隔，留空不限制) | `CN, US, HK` |
| `BLACKLIST` | 目标域名黑名单 (禁止代理访问的域名) | `baidu.com, qq.com` |
| `WHITELIST` | 目标域名白名单 (只允许代理访问的域名) | `github.com, raw.githubusercontent.com` |
| `ENABLE_CACHE` | 是否开启 Cloudflare 缓存 (`true`/`false`) | `true` |

*(注：如果未设置环境变量，代码将使用文件顶部的 `DEFAULT_CONFIG` 默认值)*

---

## 💻 使用示例

## 假设你的 Worker 域名为 `docker.example.com`，设置的密码为 `123456`。

### 场景 1：Docker 镜像加速 (无需密码)

#### Worker 会自动检测 Docker 客户端，直接使用即可。

#### 直接拉取官方镜像 (自动补全 library):
```bash
docker pull [docker.example.com/nginx](https://docker.example.com/nginx)
docker pull [docker.example.com/mysql:8.0](https://docker.example.com/mysql:8.0)
docker pull [docker.example.com/alpine](https://docker.example.com/alpine)
```
拉取第三方镜像 (ghcr.io, quay.io 等):
```bash
# GitHub Container Registry
docker pull [docker.example.com/ghcr.io/username/image:tag](https://docker.example.com/ghcr.io/username/image:tag)

# Google Container Registry
docker pull [docker.example.com/gcr.io/google-samples/hello-app:1.0](https://docker.example.com/gcr.io/google-samples/hello-app:1.0)
```

# ❓ 常见问题
## Q: 为什么浏览器直接访问 /v2/ 路径返回 404？
### A: 这是为了安全。脚本检测到非 Docker 客户端（如 Chrome）访问 Docker API 路径时，会故意返回 404 隐藏服务。

## Q: 为什么拉取大镜像层时通过了，但速度不快？
### A: Worker 对流式传输进行了优化，但速度仍受限于 Cloudflare 边缘节点到源站（如 Docker Hub）的连接质量。开启 ENABLE_CACHE 可以加速热门镜像的二次拉取。

## Q: 出现 403 Forbidden 怎么回事？ 
### 1.检查是否触发了 BLACKLIST 黑名单。

### 2.检查你的 IP/国家是否在允许列表中。

### 3.如果是 Docker 拉取，脚本已自动处理 S3 签名问题，请确保你的 Worker 域名没有被墙。

# 许可证
## 本项目基于 MIT 许可证开源。

# 致谢与声明
## 本项目基于 [fscarmen2/Cloudflare-Accel](https://github.com/fscarmen2/Cloudflare-Accel) 进行二次开发。

### 借鉴了原作者的 HTML 界面样式。

### 参考并改进了 Docker 镜像加速 的核心逻辑。

### 在此对原作者表示感谢！
