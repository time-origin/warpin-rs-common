use chrono::{DateTime, Duration, Utc};
use reqwest::Url;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::sync::Arc;
use tokio::sync::RwLock;
use warpin_errors::{Result, ServiceError};

const DEFAULT_API_BASE: &str = "https://api.dingtalk.com";
const DEFAULT_OAPI_BASE: &str = "https://oapi.dingtalk.com";

#[derive(Clone, Debug, Deserialize)]
pub struct DingTalkConfig {
    pub app_key: String,
    pub app_secret: String,
    #[serde(default = "default_api_base")]
    pub api_base: String,
    #[serde(default = "default_oapi_base")]
    pub oapi_base: String,
}

impl DingTalkConfig {
    pub fn validate(&self) -> Result<()> {
        if self.app_key.trim().is_empty() {
            return Err(ServiceError::bad_request("dingtalk.app_key is required"));
        }
        if self.app_secret.trim().is_empty() {
            return Err(ServiceError::bad_request("dingtalk.app_secret is required"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct DingTalkClient {
    config: DingTalkConfig,
    http: reqwest::Client,
    token: Arc<RwLock<Option<CachedToken>>>,
}

impl DingTalkClient {
    pub fn new(config: DingTalkConfig) -> Result<Self> {
        config.validate()?;

        Ok(Self {
            config,
            http: reqwest::Client::new(),
            token: Arc::new(RwLock::new(None)),
        })
    }

    pub fn with_http_client(config: DingTalkConfig, http: reqwest::Client) -> Result<Self> {
        config.validate()?;

        Ok(Self {
            config,
            http,
            token: Arc::new(RwLock::new(None)),
        })
    }

    pub async fn access_token(&self) -> Result<String> {
        if let Some(token) = self.valid_cached_token().await {
            return Ok(token);
        }

        let mut guard = self.token.write().await;
        if let Some(token) = guard.as_ref().filter(|token| token.is_valid()) {
            return Ok(token.value.clone());
        }

        let token = self.fetch_access_token().await?;
        let value = token.access_token.clone();
        *guard = Some(CachedToken::from_response(token));
        Ok(value)
    }

    pub async fn get_attendance_records(
        &self,
        request: AttendanceRecordRequest,
    ) -> Result<AttendanceRecordResponse> {
        self.post_oapi_with_token("/attendance/listRecord", &request)
            .await
    }

    pub async fn get_attendance_details(
        &self,
        request: AttendanceDetailRequest,
    ) -> Result<AttendanceDetailResponse> {
        self.post_oapi_with_token("/attendance/list", &request)
            .await
    }

    pub async fn post_oapi_with_token<T, R>(&self, path: &str, body: &T) -> Result<R>
    where
        T: Serialize + ?Sized,
        R: DeserializeOwned,
    {
        let token = self.access_token().await?;
        let mut url = self.oapi_url(path)?;
        url.query_pairs_mut().append_pair("access_token", &token);

        let envelope: OapiEnvelope<R> = self
            .http
            .post(url)
            .json(body)
            .send()
            .await
            .map_err(map_transport_error)?
            .error_for_status()
            .map_err(map_status_error)?
            .json()
            .await
            .map_err(map_decode_error)?;

        envelope.into_result()
    }

    async fn valid_cached_token(&self) -> Option<String> {
        self.token
            .read()
            .await
            .as_ref()
            .filter(|token| token.is_valid())
            .map(|token| token.value.clone())
    }

    async fn fetch_access_token(&self) -> Result<AccessTokenResponse> {
        let url = self.api_url("/v1.0/oauth2/accessToken")?;
        let request = AccessTokenRequest {
            app_key: self.config.app_key.clone(),
            app_secret: self.config.app_secret.clone(),
        };

        self.http
            .post(url)
            .json(&request)
            .send()
            .await
            .map_err(map_transport_error)?
            .error_for_status()
            .map_err(map_status_error)?
            .json()
            .await
            .map_err(map_decode_error)
    }

    fn api_url(&self, path: &str) -> Result<Url> {
        join_url(&self.config.api_base, path)
    }

    fn oapi_url(&self, path: &str) -> Result<Url> {
        join_url(&self.config.oapi_base, path)
    }
}

#[derive(Clone, Debug)]
struct CachedToken {
    value: String,
    expires_at: DateTime<Utc>,
}

impl CachedToken {
    fn from_response(response: AccessTokenResponse) -> Self {
        let ttl = response.expire_in.saturating_sub(120).max(60);
        Self {
            value: response.access_token,
            expires_at: Utc::now() + Duration::seconds(ttl),
        }
    }

    fn is_valid(&self) -> bool {
        Utc::now() < self.expires_at
    }
}

#[derive(Debug, Serialize)]
struct AccessTokenRequest {
    #[serde(rename = "appKey")]
    app_key: String,
    #[serde(rename = "appSecret")]
    app_secret: String,
}

#[derive(Clone, Debug, Deserialize)]
struct AccessTokenResponse {
    #[serde(rename = "accessToken")]
    access_token: String,
    #[serde(rename = "expireIn")]
    expire_in: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttendanceRecordRequest {
    #[serde(rename = "checkDateFrom")]
    pub check_date_from: String,
    #[serde(rename = "checkDateTo")]
    pub check_date_to: String,
    #[serde(rename = "userIds")]
    pub user_ids: Vec<String>,
    #[serde(rename = "isI18n", skip_serializing_if = "Option::is_none")]
    pub is_i18n: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttendanceRecordResponse {
    #[serde(rename = "recordresult", default)]
    pub records: Vec<AttendanceRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttendanceRecord {
    #[serde(flatten)]
    pub fields: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttendanceDetailRequest {
    #[serde(rename = "workDateFrom")]
    pub work_date_from: String,
    #[serde(rename = "workDateTo")]
    pub work_date_to: String,
    #[serde(rename = "userIdList")]
    pub user_id_list: Vec<String>,
    pub offset: u64,
    pub limit: u64,
    #[serde(rename = "isI18n", skip_serializing_if = "Option::is_none")]
    pub is_i18n: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttendanceDetailResponse {
    #[serde(default)]
    pub has_more: bool,
    #[serde(rename = "recordresult", default)]
    pub records: Vec<AttendanceDetail>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttendanceDetail {
    #[serde(flatten)]
    pub fields: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct OapiEnvelope<T> {
    #[serde(default)]
    errcode: i64,
    #[serde(default)]
    errmsg: String,
    #[serde(flatten)]
    data: T,
}

impl<T> OapiEnvelope<T> {
    fn into_result(self) -> Result<T> {
        if self.errcode == 0 {
            Ok(self.data)
        } else {
            Err(ServiceError::service_unavailable(format!(
                "dingtalk api error {}: {}",
                self.errcode, self.errmsg
            )))
        }
    }
}

fn default_api_base() -> String {
    DEFAULT_API_BASE.to_string()
}

fn default_oapi_base() -> String {
    DEFAULT_OAPI_BASE.to_string()
}

fn join_url(base: &str, path: &str) -> Result<Url> {
    let base = base.trim_end_matches('/');
    let path = path.trim_start_matches('/');
    Url::parse(&format!("{base}/{path}")).map_err(|error| {
        ServiceError::bad_request(format!("invalid dingtalk url {base}/{path}: {error}"))
    })
}

fn map_transport_error(error: reqwest::Error) -> ServiceError {
    ServiceError::service_unavailable(format!("dingtalk request failed: {error}"))
}

fn map_status_error(error: reqwest::Error) -> ServiceError {
    ServiceError::service_unavailable(format!("dingtalk http status error: {error}"))
}

fn map_decode_error(error: reqwest::Error) -> ServiceError {
    ServiceError::service_unavailable(format!("failed to decode dingtalk response: {error}"))
}
