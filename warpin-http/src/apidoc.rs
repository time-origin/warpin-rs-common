//! API 文档 UI 组件 — 基于 [RapiDoc](https://rapidocweb.com)
//!
//! 封装 RapiDoc Web Component，为 Axum 服务提供开箱即用的 API 文档浏览与在线调试能力。
//! 可用于单服务独立文档或 Gateway 多服务聚合文档。
//!
//! # 快速开始
//!
//! ```rust,ignore
//! use warpin_http::apidoc::ApiDoc;
//! use axum::Router;
//!
//! // 单服务 — 一行接入
//! let routes = Router::new()
//!     .merge(ApiDoc::new("/docs").spec("API", "/openapi.json").into_router::<()>());
//!
//! // Gateway 聚合多服务
//! let routes = Router::new()
//!     .merge(
//!         ApiDoc::new("/docs")
//!             .title("TTC Platform API")
//!             .spec("Scheduler", "/api-docs/scheduler.json")
//!             .spec("Dataflow", "/api-docs/dataflow.json")
//!             .into_router::<()>(),
//!     );
//! ```

use axum::{Router, response::Html, routing::get};

/// RapiDoc JS 默认 CDN 地址（自动获取最新稳定版）
const DEFAULT_JS_URL: &str = "https://unpkg.com/rapidoc/dist/rapidoc-min.js";

// ── 主题 ──────────────────────────────────────────────────────────────────

/// API 文档主题
#[derive(Debug, Clone, Copy, Default)]
pub enum ApiDocTheme {
    /// 亮色主题
    #[default]
    Light,
    /// 暗色主题
    Dark,
}

impl ApiDocTheme {
    fn as_str(self) -> &'static str {
        match self {
            Self::Light => "light",
            Self::Dark => "dark",
        }
    }

    fn nav_bg(self) -> &'static str {
        match self {
            Self::Light => "#f7f7f7",
            Self::Dark => "#1e1e2e",
        }
    }

    fn nav_text(self) -> &'static str {
        match self {
            Self::Light => "#333333",
            Self::Dark => "#cdd6f4",
        }
    }

    fn nav_hover_bg(self) -> &'static str {
        match self {
            Self::Light => "#e9ecef",
            Self::Dark => "#313244",
        }
    }
}

// ── 构建器 ────────────────────────────────────────────────────────────────

/// API 文档 UI 组件
///
/// 通过 Builder 模式配置后，调用 [`into_router`](Self::into_router) 生成 Axum Router，
/// 直接 `.merge()` 到已有路由即可。
///
/// # 多规格支持
///
/// 注册多个 spec 时，页面顶部自动出现下拉选择器，用户可切换查看不同服务的 API 文档。
///
/// # 自定义 RapiDoc JS 来源
///
/// 默认从 CDN 加载。离线 / 内网环境可通过 [`js_url`](Self::js_url) 指向自托管文件：
///
/// ```rust,ignore
/// ApiDoc::new("/docs")
///     .js_url("/static/rapidoc-min.js")
///     .spec("API", "/openapi.json")
/// ```
#[derive(Debug, Clone)]
pub struct ApiDoc {
    path: String,
    title: String,
    specs: Vec<(String, String)>,
    theme: ApiDocTheme,
    primary_color: String,
    allow_try: bool,
    render_style: String,
    js_url: String,
}

impl ApiDoc {
    /// 创建 API 文档组件，指定挂载路径（如 `/docs`）
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            title: "API Documentation".into(),
            specs: Vec::new(),
            theme: ApiDocTheme::default(),
            primary_color: "#0078d4".into(),
            allow_try: true,
            render_style: "read".into(),
            js_url: DEFAULT_JS_URL.into(),
        }
    }

    /// 设置文档页面标题
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = title.into();
        self
    }

    /// 添加一个 OpenAPI 规格源
    ///
    /// - `name` — 显示名称（多规格时出现在下拉选择器中）
    /// - `url`  — OpenAPI JSON 的 URL 路径（相对于当前域名）
    pub fn spec(mut self, name: impl Into<String>, url: impl Into<String>) -> Self {
        self.specs.push((name.into(), url.into()));
        self
    }

    /// 批量添加 OpenAPI 规格源
    pub fn specs(
        mut self,
        specs: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        for (name, url) in specs {
            self.specs.push((name.into(), url.into()));
        }
        self
    }

    /// 设置主题（默认 Light）
    pub fn theme(mut self, theme: ApiDocTheme) -> Self {
        self.theme = theme;
        self
    }

    /// 设置主色调（CSS 颜色值，默认 `#0078d4`）
    pub fn primary_color(mut self, color: impl Into<String>) -> Self {
        self.primary_color = color.into();
        self
    }

    /// 是否启用在线调试 Try It（默认 true）
    pub fn allow_try(mut self, allow: bool) -> Self {
        self.allow_try = allow;
        self
    }

    /// 渲染风格：`read`（默认，适合阅读）、`view`（紧凑）、`focused`（逐个聚焦）
    pub fn render_style(mut self, style: impl Into<String>) -> Self {
        self.render_style = style.into();
        self
    }

    /// 自定义 RapiDoc JS 文件地址（默认从 CDN 加载）
    ///
    /// 用于离线 / 内网部署场景，可指向本地静态文件。
    pub fn js_url(mut self, url: impl Into<String>) -> Self {
        self.js_url = url.into();
        self
    }

    /// 构建 Axum Router，可直接 `.merge()` 到服务路由
    pub fn into_router<S>(self) -> Router<S>
    where
        S: Clone + Send + Sync + 'static,
    {
        let html = self.render_html();
        let path = self.path.trim_end_matches('/').to_string();
        let path_trailing = format!("{path}/");

        let html2 = html.clone();
        Router::new()
            .route(
                &path,
                get(move || {
                    let body = html.clone();
                    async move { Html(body) }
                }),
            )
            .route(
                &path_trailing,
                get(move || {
                    let body = html2.clone();
                    async move { Html(body) }
                }),
            )
    }

    /// 渲染 RapiDoc HTML 页面
    fn render_html(&self) -> String {
        let default_spec_url = self
            .specs
            .first()
            .map(|(_, url)| url.as_str())
            .unwrap_or("");

        let spec_selector = self.build_spec_selector();

        format!(
            r##"<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{title}</title>
  <style>
    html, body {{ margin:0; padding:0; height:100%; overflow:hidden; }}
    rapi-doc {{ width:100%; height:100vh; }}
  </style>
</head>
<body>
  <rapi-doc id="rapidoc"
    spec-url="{default_spec_url}"
    theme="{theme}"
    render-style="{render_style}"
    primary-color="{primary_color}"
    show-header="true"
    heading-text="{heading}"
    allow-try="{allow_try}"
    allow-authentication="true"
    allow-server-selection="true"
    show-method-in-nav-bar="as-colored-text"
    nav-bg-color="{nav_bg}"
    nav-text-color="{nav_text}"
    nav-hover-bg-color="{nav_hover_bg}"
    nav-accent-color="{primary_color}"
    regular-font="system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif"
    mono-font="ui-monospace, 'Cascadia Code', 'Fira Code', Consolas, monospace"
    load-fonts="false"
    schema-style="table"
    default-schema-tab="example"
    response-area-height="400px"
  >{spec_selector}
  </rapi-doc>
  <script type="module" src="{js_url}"></script>
</body>
</html>"##,
            title = escape_html(&self.title),
            heading = escape_html(&self.title),
            default_spec_url = escape_html(default_spec_url),
            theme = self.theme.as_str(),
            render_style = escape_html(&self.render_style),
            primary_color = escape_html(&self.primary_color),
            allow_try = if self.allow_try { "true" } else { "false" },
            nav_bg = self.theme.nav_bg(),
            nav_text = self.theme.nav_text(),
            nav_hover_bg = self.theme.nav_hover_bg(),
            spec_selector = spec_selector,
            js_url = escape_html(&self.js_url),
        )
    }

    /// 构建多规格下拉选择器（单个规格时不渲染）
    fn build_spec_selector(&self) -> String {
        if self.specs.len() <= 1 {
            return String::new();
        }

        let options: String = self
            .specs
            .iter()
            .map(|(name, url)| {
                format!(
                    r#"            <option value="{url}">{name}</option>"#,
                    url = escape_html(url),
                    name = escape_html(name),
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        format!(
            r#"
    <div slot="nav-logo" style="display:flex;align-items:center;gap:10px;padding:8px 16px;width:100%;box-sizing:border-box">
      <label style="font-size:13px;color:var(--nav-text-color);white-space:nowrap;font-weight:500">API:</label>
      <select id="api-spec-selector"
        onchange="document.getElementById('rapidoc').setAttribute('spec-url',this.value)"
        style="flex:1;padding:6px 10px;border:1px solid var(--nav-text-color,#999);border-radius:4px;
               background:var(--nav-bg-color,#fff);color:var(--nav-text-color,#333);
               font-size:13px;cursor:pointer;max-width:300px;outline:none">
{options}
      </select>
    </div>"#,
        )
    }
}

/// 基本 HTML 转义，防止注入
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

// ── 测试 ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_spec_no_selector() {
        let html = ApiDoc::new("/docs")
            .title("Test API")
            .spec("My API", "/openapi.json")
            .render_html();

        assert!(html.contains("Test API"));
        assert!(html.contains(r#"spec-url="/openapi.json""#));
        assert!(
            !html.contains("api-spec-selector"),
            "single spec should not render selector"
        );
    }

    #[test]
    fn multiple_specs_render_selector() {
        let html = ApiDoc::new("/docs")
            .title("Platform")
            .spec("Service A", "/a.json")
            .spec("Service B", "/b.json")
            .render_html();

        assert!(html.contains("api-spec-selector"));
        assert!(html.contains("/a.json"));
        assert!(html.contains("/b.json"));
        assert!(html.contains("Service A"));
        assert!(html.contains("Service B"));
        // 默认选中第一个
        assert!(html.contains(r#"spec-url="/a.json""#));
    }

    #[test]
    fn dark_theme() {
        let html = ApiDoc::new("/docs")
            .theme(ApiDocTheme::Dark)
            .spec("API", "/openapi.json")
            .render_html();

        assert!(html.contains(r#"theme="dark""#));
        assert!(html.contains(r##"nav-bg-color="#1e1e2e""##));
    }

    #[test]
    fn custom_js_url() {
        let html = ApiDoc::new("/docs")
            .js_url("/static/rapidoc-min.js")
            .spec("API", "/openapi.json")
            .render_html();

        assert!(html.contains(r#"src="/static/rapidoc-min.js""#));
        assert!(!html.contains("unpkg.com"));
    }

    #[test]
    fn html_escaping() {
        let html = ApiDoc::new("/docs")
            .title(r#"A & B <script>"#)
            .spec("test", "/api.json")
            .render_html();

        assert!(html.contains("A &amp; B &lt;script&gt;"));
        assert!(!html.contains("<script>\""));
    }

    #[test]
    fn disable_try_it() {
        let html = ApiDoc::new("/docs")
            .allow_try(false)
            .spec("API", "/openapi.json")
            .render_html();

        assert!(html.contains(r#"allow-try="false""#));
    }
}
