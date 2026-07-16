use chrono::{DateTime, Duration as ChronoDuration, Utc};
use reqwest::Url;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    fmt,
    sync::{Arc, Mutex as StdMutex},
    time::Duration as StdDuration,
};
use tokio::sync::watch;
use warpin_errors::{Result, ServiceError};

const DEFAULT_API_BASE: &str = "https://api.dingtalk.com";
const DEFAULT_OAPI_BASE: &str = "https://oapi.dingtalk.com";
const REDACTED: &str = "[REDACTED]";
const MIN_TRANSPORT_TIMEOUT: StdDuration = StdDuration::from_millis(100);
const MAX_TRANSPORT_TIMEOUT: StdDuration = StdDuration::from_secs(120);
const MAX_ACCESS_TOKEN_BYTES: usize = 16 * 1024;
const MAX_ACCESS_TOKEN_TTL_SECONDS: i64 = 24 * 60 * 60;
const TOKEN_CACHE_SAFETY_MARGIN_SECONDS: i64 = 120;
const MAX_TOKEN_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_API_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_ENDPOINT_BYTES: usize = 2048;

#[derive(Clone, Default, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum DingTalkEndpointPolicy {
    #[default]
    OfficialOnly,
    TrustedOrigins {
        api_origin: String,
        oapi_origin: String,
    },
}

impl fmt::Debug for DingTalkEndpointPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OfficialOnly => formatter.write_str("OfficialOnly"),
            Self::TrustedOrigins { .. } => formatter
                .debug_struct("TrustedOrigins")
                .field("api_origin", &REDACTED)
                .field("oapi_origin", &REDACTED)
                .finish(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DingTalkTransportPolicy {
    connect_timeout: StdDuration,
    request_timeout: StdDuration,
    read_timeout: StdDuration,
}

impl Default for DingTalkTransportPolicy {
    fn default() -> Self {
        Self {
            connect_timeout: StdDuration::from_secs(5),
            request_timeout: StdDuration::from_secs(30),
            read_timeout: StdDuration::from_secs(15),
        }
    }
}

impl DingTalkTransportPolicy {
    pub fn new(
        connect_timeout: StdDuration,
        request_timeout: StdDuration,
        read_timeout: StdDuration,
    ) -> Result<Self> {
        let policy = Self {
            connect_timeout,
            request_timeout,
            read_timeout,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub const fn connect_timeout(self) -> StdDuration {
        self.connect_timeout
    }

    pub const fn request_timeout(self) -> StdDuration {
        self.request_timeout
    }

    pub const fn read_timeout(self) -> StdDuration {
        self.read_timeout
    }

    fn validate(self) -> Result<()> {
        let timeouts = [
            self.connect_timeout,
            self.request_timeout,
            self.read_timeout,
        ];
        let bounded = timeouts
            .iter()
            .all(|timeout| *timeout >= MIN_TRANSPORT_TIMEOUT && *timeout <= MAX_TRANSPORT_TIMEOUT);
        let coherent = self.connect_timeout <= self.request_timeout
            && self.read_timeout <= self.request_timeout;
        if bounded && coherent {
            Ok(())
        } else {
            Err(
                DingTalkBoundaryError::new(DingTalkBoundaryErrorKind::TransportPolicy, false)
                    .into_service_error(),
            )
        }
    }
}

#[derive(Clone, Deserialize)]
pub struct DingTalkConfig {
    #[serde(default)]
    pub corp_id: Option<String>,
    #[serde(default)]
    pub app_id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    pub app_key: String,
    pub app_secret: String,
    #[serde(default)]
    pub callback_token: Option<String>,
    #[serde(default = "default_api_base")]
    pub api_base: String,
    #[serde(default = "default_oapi_base")]
    pub oapi_base: String,
}

impl fmt::Debug for DingTalkConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DingTalkConfig")
            .field("corp_id", &self.corp_id.as_ref().map(|_| REDACTED))
            .field("app_id", &self.app_id.as_ref().map(|_| REDACTED))
            .field("agent_id", &self.agent_id.as_ref().map(|_| REDACTED))
            .field("app_key", &REDACTED)
            .field("app_secret", &REDACTED)
            .field(
                "callback_token",
                &self.callback_token.as_ref().map(|_| REDACTED),
            )
            .field("api_base", &REDACTED)
            .field("oapi_base", &REDACTED)
            .finish()
    }
}

impl DingTalkConfig {
    pub fn validate(&self) -> Result<()> {
        self.validate_credentials()?;
        self.validated_bases(&DingTalkEndpointPolicy::default())?;
        Ok(())
    }

    fn validate_credentials(&self) -> Result<()> {
        if self.app_key.trim().is_empty() {
            return Err(ServiceError::bad_request("dingtalk.app_key is required"));
        }
        if self.app_secret.trim().is_empty() {
            return Err(ServiceError::bad_request("dingtalk.app_secret is required"));
        }
        Ok(())
    }

    fn validated_bases(&self, policy: &DingTalkEndpointPolicy) -> Result<(Url, Url)> {
        let api_base = validate_endpoint_base(&self.api_base)?;
        let oapi_base = validate_endpoint_base(&self.oapi_base)?;
        policy.validate_bases(&api_base, &oapi_base)?;
        Ok((api_base, oapi_base))
    }
}

#[derive(Clone)]
pub struct DingTalkClient {
    config: DingTalkConfig,
    api_base: Url,
    oapi_base: Url,
    http: reqwest::Client,
    token_refresh: Arc<TokenRefreshCoordinator>,
    token_refresh_timeout: StdDuration,
}

struct TokenRefreshCoordinator {
    state: StdMutex<TokenRefreshState>,
}

#[derive(Default)]
struct TokenRefreshState {
    cached: Option<CachedToken>,
    in_flight: Option<Arc<TokenRefreshOperation>>,
}

struct TokenRefreshOperation {
    completion: watch::Sender<Option<Result<String>>>,
}

enum TokenRefreshAction {
    Cached(String),
    Join(Arc<TokenRefreshOperation>),
    Start(Arc<TokenRefreshOperation>),
}

struct ValidatedAccessToken {
    value: String,
    cached: Option<CachedToken>,
}

impl TokenRefreshCoordinator {
    fn new() -> Self {
        Self {
            state: StdMutex::new(TokenRefreshState::default()),
        }
    }

    fn acquire(&self) -> Result<TokenRefreshAction> {
        let mut state = self.state.lock().map_err(|_| token_refresh_error())?;
        if let Some(value) = state
            .cached
            .as_ref()
            .filter(|token| token.is_valid())
            .map(|token| token.value.clone())
        {
            return Ok(TokenRefreshAction::Cached(value));
        }
        state.cached = None;

        if let Some(operation) = &state.in_flight {
            return Ok(TokenRefreshAction::Join(operation.clone()));
        }

        let operation = Arc::new(TokenRefreshOperation::new());
        state.in_flight = Some(operation.clone());
        Ok(TokenRefreshAction::Start(operation))
    }

    fn complete(
        &self,
        operation: &Arc<TokenRefreshOperation>,
        result: Result<ValidatedAccessToken>,
    ) {
        let shared_result = match self.state.lock() {
            Ok(mut state) => {
                let owns_generation = state
                    .in_flight
                    .as_ref()
                    .is_some_and(|active| Arc::ptr_eq(active, operation));
                if !owns_generation {
                    Err(token_refresh_error())
                } else {
                    state.in_flight = None;
                    match result {
                        Ok(validated) => {
                            let value = validated.value.clone();
                            state.cached = validated.cached;
                            Ok(value)
                        }
                        Err(error) => Err(error),
                    }
                }
            }
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                if state
                    .in_flight
                    .as_ref()
                    .is_some_and(|active| Arc::ptr_eq(active, operation))
                {
                    state.in_flight = None;
                }
                state.cached = None;
                Err(token_refresh_error())
            }
        };
        operation.complete(shared_result);
    }
}

impl TokenRefreshOperation {
    fn new() -> Self {
        let (completion, _) = watch::channel(None);
        Self { completion }
    }

    async fn wait(&self) -> Result<String> {
        let mut completion = self.completion.subscribe();
        loop {
            if let Some(result) = completion.borrow().clone() {
                return result;
            }
            completion
                .changed()
                .await
                .map_err(|_| token_refresh_error())?;
        }
    }

    fn complete(&self, result: Result<String>) {
        self.completion.send_if_modified(|current| {
            if current.is_some() {
                false
            } else {
                *current = Some(result);
                true
            }
        });
    }
}

fn token_refresh_error() -> ServiceError {
    DingTalkBoundaryError::new(DingTalkBoundaryErrorKind::Transport, true).into_service_error()
}

fn response_decode_error() -> ServiceError {
    DingTalkBoundaryError::new(DingTalkBoundaryErrorKind::ResponseDecode, false)
        .into_service_error()
}

impl fmt::Debug for DingTalkClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DingTalkClient")
            .field("config", &self.config)
            .field("api_base", &REDACTED)
            .field("oapi_base", &REDACTED)
            .field("http", &REDACTED)
            .field("token", &REDACTED)
            .field("token_refresh", &REDACTED)
            .field("token_refresh_timeout", &self.token_refresh_timeout)
            .finish()
    }
}

impl DingTalkClient {
    pub fn new(config: DingTalkConfig) -> Result<Self> {
        Self::with_policies(
            config,
            DingTalkEndpointPolicy::default(),
            DingTalkTransportPolicy::default(),
        )
    }

    pub fn with_endpoint_policy(
        config: DingTalkConfig,
        endpoint_policy: DingTalkEndpointPolicy,
    ) -> Result<Self> {
        Self::with_policies(config, endpoint_policy, DingTalkTransportPolicy::default())
    }

    pub fn with_policies(
        config: DingTalkConfig,
        endpoint_policy: DingTalkEndpointPolicy,
        transport_policy: DingTalkTransportPolicy,
    ) -> Result<Self> {
        config.validate_credentials()?;
        let (api_base, oapi_base) = config.validated_bases(&endpoint_policy)?;
        transport_policy.validate()?;
        let http = build_http_client(transport_policy)?;

        Ok(Self {
            config,
            api_base,
            oapi_base,
            http,
            token_refresh: Arc::new(TokenRefreshCoordinator::new()),
            token_refresh_timeout: transport_policy.request_timeout(),
        })
    }

    pub async fn access_token(&self) -> Result<String> {
        tokio::time::timeout(
            self.token_refresh_timeout,
            self.access_token_before_deadline(),
        )
        .await
        .map_err(|_| {
            DingTalkBoundaryError::new(DingTalkBoundaryErrorKind::Transport, true)
                .into_service_error()
        })?
    }

    async fn access_token_before_deadline(&self) -> Result<String> {
        match self.token_refresh.acquire()? {
            TokenRefreshAction::Cached(value) => Ok(value),
            TokenRefreshAction::Join(operation) => operation.wait().await,
            TokenRefreshAction::Start(operation) => {
                self.spawn_access_token_refresh(operation.clone());
                operation.wait().await
            }
        }
    }

    fn spawn_access_token_refresh(&self, operation: Arc<TokenRefreshOperation>) {
        let worker_client = self.clone();
        self.spawn_access_token_refresh_worker(operation, async move {
            worker_client.fetch_validated_access_token().await
        });
    }

    fn spawn_access_token_refresh_worker<F>(&self, operation: Arc<TokenRefreshOperation>, worker: F)
    where
        F: std::future::Future<Output = Result<ValidatedAccessToken>> + Send + 'static,
    {
        let worker = tokio::spawn(worker);
        let supervisor = self.clone();
        tokio::spawn(async move {
            let result = worker.await.unwrap_or_else(|_| Err(token_refresh_error()));
            supervisor.token_refresh.complete(&operation, result);
        });
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

    pub async fn list_departments(
        &self,
        request: DepartmentListRequest,
    ) -> Result<DepartmentListResult> {
        let response: DepartmentListResponse = self
            .post_oapi_with_token("/topapi/v2/department/listsub", &request)
            .await?;
        Ok(response.result)
    }

    pub async fn list_department_users(
        &self,
        request: DepartmentUserListRequest,
    ) -> Result<DepartmentUserListResult> {
        let response: DepartmentUserListResponse = self
            .post_oapi_with_token("/topapi/v2/user/list", &request)
            .await?;
        Ok(response.result)
    }

    pub async fn get_user(&self, request: UserGetRequest) -> Result<DingTalkUser> {
        let response: UserGetResponse = self
            .post_oapi_with_token("/topapi/v2/user/get", &request)
            .await?;
        Ok(response.result)
    }

    pub async fn get_process_code_by_name(
        &self,
        request: ProcessCodeByNameRequest,
    ) -> Result<ProcessCodeByNameResult> {
        let response: ProcessCodeByNameResponse = self
            .post_oapi_with_token("/topapi/process/get_by_name", &request)
            .await?;
        Ok(response.into_result())
    }

    pub async fn list_processes_by_user(
        &self,
        request: ProcessListByUserRequest,
    ) -> Result<ProcessListByUserResult> {
        let response: ProcessListByUserResponse = self
            .post_oapi_with_token("/topapi/process/listbyuserid", &request)
            .await?;
        Ok(response.result)
    }

    pub async fn query_approval_instance_ids(
        &self,
        request: ApprovalInstanceIdListRequest,
    ) -> Result<ApprovalInstanceIdListResponse> {
        let response: ApprovalInstanceIdListApiResponse = self
            .post_api_with_token("/v1.0/workflow/processes/instanceIds/query", &request)
            .await?;
        Ok(response.result)
    }

    pub async fn get_approval_attachment_download_url(
        &self,
        request: ApprovalAttachmentDownloadUrlRequest,
    ) -> Result<ApprovalAttachmentDownloadUrlResult> {
        let response: ApprovalAttachmentDownloadUrlResponse = self
            .post_oapi_with_token("/topapi/processinstance/file/url/get", &request)
            .await?;
        Ok(response.result)
    }

    pub async fn list_holiday_types(
        &self,
        request: HolidayTypeListRequest,
    ) -> Result<HolidayTypeListResult> {
        let response: HolidayTypeListResponse = self
            .post_oapi_with_token("/topapi/attendance/vacation/type/list", &request)
            .await?;
        Ok(response.result)
    }

    pub async fn list_attendance_groups(
        &self,
        request: AttendanceGroupListRequest,
    ) -> Result<AttendanceGroupListResult> {
        let response: AttendanceGroupListResponse = self
            .post_oapi_with_token("/topapi/attendance/group/minimalism/list", &request)
            .await?;
        Ok(response.result)
    }

    pub async fn get_attendance_group(
        &self,
        request: AttendanceGroupGetRequest,
    ) -> Result<AttendanceGroupDetail> {
        let response: AttendanceGroupGetResponse = self
            .post_oapi_with_token("/topapi/attendance/group/query", &request)
            .await?;
        Ok(response.result)
    }

    pub async fn get_approval_instance(
        &self,
        process_instance_id: impl AsRef<str>,
    ) -> Result<ApprovalProcessInstance> {
        let process_instance_id = process_instance_id.as_ref().trim();
        if process_instance_id.is_empty() {
            return Err(ServiceError::bad_request(
                "dingtalk process_instance_id is required",
            ));
        }

        let query = [("processInstanceId", process_instance_id.to_string())];
        let response: ApprovalProcessInstanceApiResponse = self
            .get_api_with_token("/v1.0/workflow/processInstances", &query)
            .await?;
        Ok(response.result)
    }

    pub async fn post_api_with_token<T, R>(&self, path: &str, body: &T) -> Result<R>
    where
        T: Serialize + ?Sized,
        R: DeserializeOwned,
    {
        let token = self.access_token().await?;
        let url = self.api_url(path)?;

        let response = self
            .http
            .post(url)
            .header("x-acs-dingtalk-access-token", token)
            .json(body)
            .send()
            .await
            .map_err(map_transport_error)?
            .ensure_success()
            .await?;
        let envelope: ApiEnvelope<R> =
            decode_bounded_json(response, MAX_API_RESPONSE_BYTES).await?;

        envelope.into_result()
    }

    pub async fn get_api_with_token<R>(&self, path: &str, query: &[(&str, String)]) -> Result<R>
    where
        R: DeserializeOwned,
    {
        let token = self.access_token().await?;
        let mut url = self.api_url(path)?;
        url.query_pairs_mut()
            .extend_pairs(query.iter().map(|(key, value)| (*key, value.as_str())));

        let response = self
            .http
            .get(url)
            .header("x-acs-dingtalk-access-token", token)
            .send()
            .await
            .map_err(map_transport_error)?
            .ensure_success()
            .await?;
        let envelope: ApiEnvelope<R> =
            decode_bounded_json(response, MAX_API_RESPONSE_BYTES).await?;

        envelope.into_result()
    }

    pub async fn post_oapi_with_token<T, R>(&self, path: &str, body: &T) -> Result<R>
    where
        T: Serialize + ?Sized,
        R: DeserializeOwned,
    {
        let token = self.access_token().await?;
        let mut url = self.oapi_url(path)?;
        url.query_pairs_mut().append_pair("access_token", &token);

        let response = self
            .http
            .post(url)
            .json(body)
            .send()
            .await
            .map_err(map_transport_error)?
            .ensure_success()
            .await?;
        let envelope: OapiEnvelope<R> =
            decode_bounded_json(response, MAX_API_RESPONSE_BYTES).await?;

        envelope.into_result()
    }

    async fn fetch_access_token(&self) -> Result<AccessTokenResponse> {
        let url = self.api_url("/v1.0/oauth2/accessToken")?;
        let request = AccessTokenRequest {
            app_key: self.config.app_key.clone(),
            app_secret: self.config.app_secret.clone(),
        };

        let response = self
            .http
            .post(url)
            .json(&request)
            .send()
            .await
            .map_err(map_transport_error)?
            .ensure_success()
            .await?;
        decode_bounded_json(response, MAX_TOKEN_RESPONSE_BYTES).await
    }

    async fn fetch_validated_access_token(&self) -> Result<ValidatedAccessToken> {
        self.fetch_access_token().await?.into_validated()
    }

    fn api_url(&self, path: &str) -> Result<Url> {
        join_url(&self.api_base, path)
    }

    fn oapi_url(&self, path: &str) -> Result<Url> {
        join_url(&self.oapi_base, path)
    }
}

#[derive(Clone)]
struct CachedToken {
    value: String,
    expires_at: DateTime<Utc>,
}

impl fmt::Debug for CachedToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CachedToken")
            .field("value", &REDACTED)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl CachedToken {
    fn is_valid(&self) -> bool {
        Utc::now() < self.expires_at
    }
}

#[derive(Serialize)]
struct AccessTokenRequest {
    #[serde(rename = "appKey")]
    app_key: String,
    #[serde(rename = "appSecret")]
    app_secret: String,
}

impl fmt::Debug for AccessTokenRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccessTokenRequest")
            .field("app_key", &REDACTED)
            .field("app_secret", &REDACTED)
            .finish()
    }
}

#[derive(Clone, Deserialize)]
struct AccessTokenResponse {
    #[serde(rename = "accessToken")]
    access_token: String,
    #[serde(rename = "expireIn")]
    expire_in: i64,
}

impl fmt::Debug for AccessTokenResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccessTokenResponse")
            .field("access_token", &REDACTED)
            .field("expire_in", &self.expire_in)
            .finish()
    }
}

impl AccessTokenResponse {
    fn into_validated(self) -> Result<ValidatedAccessToken> {
        let token_is_valid = !self.access_token.is_empty()
            && self.access_token.len() <= MAX_ACCESS_TOKEN_BYTES
            && self.access_token.is_ascii()
            && self
                .access_token
                .bytes()
                .all(|byte| (b'!'..=b'~').contains(&byte));
        let ttl_is_valid = self.expire_in > 0 && self.expire_in <= MAX_ACCESS_TOKEN_TTL_SECONDS;
        if !token_is_valid || !ttl_is_valid {
            return Err(response_decode_error());
        }

        let value = self.access_token;
        let cache_ttl = (self.expire_in - TOKEN_CACHE_SAFETY_MARGIN_SECONDS).max(0);
        let cached = if cache_ttl == 0 {
            None
        } else {
            let duration =
                ChronoDuration::try_seconds(cache_ttl).ok_or_else(response_decode_error)?;
            let expires_at = Utc::now()
                .checked_add_signed(duration)
                .ok_or_else(response_decode_error)?;
            Some(CachedToken {
                value: value.clone(),
                expires_at,
            })
        };

        Ok(ValidatedAccessToken { value, cached })
    }
}

#[derive(Clone, Serialize, Deserialize)]
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

#[derive(Clone, Serialize, Deserialize)]
pub struct AttendanceRecordResponse {
    #[serde(rename = "recordresult", default)]
    pub records: Vec<AttendanceRecord>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AttendanceRecord {
    #[serde(flatten)]
    pub fields: serde_json::Value,
}

#[derive(Clone, Serialize, Deserialize)]
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

#[derive(Clone, Serialize, Deserialize)]
pub struct AttendanceDetailResponse {
    #[serde(default)]
    pub has_more: bool,
    #[serde(rename = "recordresult", default)]
    pub records: Vec<AttendanceDetail>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AttendanceDetail {
    #[serde(flatten)]
    pub fields: serde_json::Value,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct DepartmentListRequest {
    #[serde(rename = "dept_id", skip_serializing_if = "Option::is_none")]
    pub dept_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct DepartmentListResponse {
    #[serde(default, deserialize_with = "deserialize_department_list_result")]
    pub result: DepartmentListResult,
}

pub type DepartmentListResult = Vec<DingTalkDepartment>;

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct DingTalkDepartment {
    #[serde(rename = "dept_id", alias = "deptId", default)]
    pub dept_id: Option<i64>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(rename = "parent_id", alias = "parentId", default)]
    pub parent_id: Option<i64>,
    #[serde(rename = "create_dept_group", alias = "createDeptGroup", default)]
    pub create_dept_group: Option<bool>,
    #[serde(rename = "auto_add_user", alias = "autoAddUser", default)]
    pub auto_add_user: Option<bool>,
    #[serde(default)]
    pub ext: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

fn deserialize_department_list_result<'de, D>(
    deserializer: D,
) -> std::result::Result<DepartmentListResult, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Payload {
        List(Vec<DingTalkDepartment>),
        Object {
            #[serde(default, alias = "departments")]
            list: Vec<DingTalkDepartment>,
            #[serde(rename = "dept_id_list", alias = "deptIdList", default)]
            dept_id_list: Vec<i64>,
        },
    }

    match Payload::deserialize(deserializer)? {
        Payload::List(list) => Ok(list),
        Payload::Object {
            list,
            dept_id_list: _,
        } if !list.is_empty() => Ok(list),
        Payload::Object { dept_id_list, .. } => Ok(dept_id_list
            .into_iter()
            .map(|dept_id| DingTalkDepartment {
                dept_id: Some(dept_id),
                ..DingTalkDepartment::default()
            })
            .collect()),
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DepartmentUserListRequest {
    #[serde(rename = "dept_id")]
    pub dept_id: i64,
    pub cursor: u64,
    pub size: u64,
    #[serde(rename = "order_field", skip_serializing_if = "Option::is_none")]
    pub order_field: Option<String>,
    #[serde(
        rename = "contain_access_limit",
        skip_serializing_if = "Option::is_none"
    )]
    pub contain_access_limit: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct DepartmentUserListResponse {
    #[serde(default)]
    pub result: DepartmentUserListResult,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct DepartmentUserListResult {
    #[serde(default)]
    pub list: Vec<DingTalkUser>,
    #[serde(rename = "has_more", alias = "hasMore", default)]
    pub has_more: bool,
    #[serde(rename = "next_cursor", alias = "nextCursor", default)]
    pub next_cursor: Option<u64>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct UserGetRequest {
    pub userid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct UserGetResponse {
    #[serde(default)]
    pub result: DingTalkUser,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct DingTalkUser {
    #[serde(rename = "userid", alias = "userId", default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub unionid: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub mobile: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(rename = "state_code", alias = "stateCode", default)]
    pub state_code: Option<String>,
    #[serde(default)]
    pub avatar: Option<String>,
    #[serde(rename = "job_number", alias = "jobNumber", default)]
    pub job_number: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(rename = "dept_id_list", alias = "deptIdList", default)]
    pub dept_id_list: Vec<i64>,
    #[serde(rename = "dept_order_list", alias = "deptOrderList", default)]
    pub dept_order_list: Vec<serde_json::Value>,
    #[serde(default)]
    pub active: Option<bool>,
    #[serde(default)]
    pub admin: Option<bool>,
    #[serde(default)]
    pub boss: Option<bool>,
    #[serde(default)]
    pub leader: Option<bool>,
    #[serde(rename = "hide_mobile", alias = "hideMobile", default)]
    pub hide_mobile: Option<bool>,
    #[serde(rename = "exclusive_account", alias = "exclusiveAccount", default)]
    pub exclusive_account: Option<bool>,
    #[serde(rename = "real_authed", alias = "realAuthed", default)]
    pub real_authed: Option<bool>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ProcessCodeByNameRequest {
    pub name: String,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct ProcessCodeByNameResponse {
    #[serde(default)]
    pub result: Option<ProcessCodeByNameResult>,
    #[serde(rename = "process_code", alias = "processCode", default)]
    pub process_code: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl ProcessCodeByNameResponse {
    fn into_result(self) -> ProcessCodeByNameResult {
        self.result.unwrap_or(ProcessCodeByNameResult {
            process_code: self.process_code,
            name: self.name,
            extra: self.extra,
        })
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct ProcessCodeByNameResult {
    #[serde(rename = "process_code", alias = "processCode", default)]
    pub process_code: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ProcessListByUserRequest {
    pub userid: String,
    pub offset: u64,
    pub size: u64,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct ProcessListByUserResponse {
    #[serde(default)]
    pub result: ProcessListByUserResult,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct ProcessListByUserResult {
    #[serde(default, alias = "process_list", alias = "processList")]
    pub list: Vec<VisibleProcess>,
    #[serde(rename = "has_more", alias = "hasMore", default)]
    pub has_more: bool,
    #[serde(rename = "next_cursor", alias = "nextCursor", default)]
    pub next_cursor: Option<u64>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct VisibleProcess {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(rename = "process_code", alias = "processCode", default)]
    pub process_code: Option<String>,
    #[serde(rename = "icon_url", alias = "iconUrl", default)]
    pub icon_url: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ApprovalInstanceIdListRequest {
    #[serde(rename = "processCode")]
    pub process_code: String,
    #[serde(rename = "startTime")]
    pub start_time: i64,
    #[serde(rename = "endTime", skip_serializing_if = "Option::is_none")]
    pub end_time: Option<i64>,
    #[serde(rename = "nextToken", skip_serializing_if = "Option::is_none")]
    pub next_token: Option<u64>,
    #[serde(rename = "maxResults", skip_serializing_if = "Option::is_none")]
    pub max_results: Option<u64>,
    #[serde(rename = "userIds", skip_serializing_if = "Option::is_none")]
    pub user_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statuses: Option<Vec<String>>,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct ApprovalInstanceIdListResponse {
    #[serde(default)]
    pub list: Vec<String>,
    #[serde(rename = "nextToken", default, skip_serializing_if = "Option::is_none")]
    pub next_token: Option<String>,
}

#[derive(Clone, Deserialize)]
struct ApprovalInstanceIdListApiResponse {
    result: ApprovalInstanceIdListResponse,
}

#[derive(Clone, Deserialize)]
struct ApprovalProcessInstanceApiResponse {
    result: ApprovalProcessInstance,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct ApprovalProcessInstance {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(rename = "createTime", default)]
    pub create_time: Option<String>,
    #[serde(rename = "finishTime", default)]
    pub finish_time: Option<String>,
    #[serde(rename = "originatorUserId", default)]
    pub originator_user_id: Option<String>,
    #[serde(rename = "originatorDeptId", default)]
    pub originator_dept_id: Option<String>,
    #[serde(rename = "originatorDeptName", default)]
    pub originator_dept_name: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub result: Option<String>,
    #[serde(rename = "businessId", default)]
    pub business_id: Option<String>,
    #[serde(rename = "approverUserIds", default)]
    pub approver_user_ids: Vec<String>,
    #[serde(rename = "ccUserIds", default)]
    pub cc_user_ids: Vec<String>,
    #[serde(rename = "formComponentValues", default)]
    pub form_component_values: Vec<ApprovalFormComponentValue>,
    #[serde(rename = "operationRecords", default)]
    pub operation_records: Vec<ApprovalOperationRecord>,
    #[serde(default)]
    pub tasks: Vec<ApprovalTask>,
    #[serde(rename = "bizAction", default)]
    pub biz_action: Option<String>,
    #[serde(rename = "bizData", default)]
    pub biz_data: Option<String>,
    #[serde(rename = "attachedProcessInstanceIds", default)]
    pub attached_process_instance_ids: Vec<String>,
    #[serde(rename = "mainProcessInstanceId", default)]
    pub main_process_instance_id: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl ApprovalProcessInstance {
    pub fn form_value_by_name(&self, name: impl AsRef<str>) -> Option<&str> {
        let name = name.as_ref();
        self.form_component_values
            .iter()
            .find(|component| component.name.as_deref() == Some(name))
            .and_then(ApprovalFormComponentValue::preferred_value)
    }

    pub fn form_value_by_biz_alias(&self, biz_alias: impl AsRef<str>) -> Option<&str> {
        let biz_alias = biz_alias.as_ref();
        self.form_component_values
            .iter()
            .find(|component| component.biz_alias.as_deref() == Some(biz_alias))
            .and_then(ApprovalFormComponentValue::preferred_value)
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct ApprovalFormComponentValue {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(rename = "extValue", default)]
    pub ext_value: Option<String>,
    #[serde(rename = "componentType", default)]
    pub component_type: Option<String>,
    #[serde(rename = "bizAlias", default)]
    pub biz_alias: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl ApprovalFormComponentValue {
    pub fn preferred_value(&self) -> Option<&str> {
        self.value.as_deref().or(self.ext_value.as_deref())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ApprovalAttachmentDownloadUrlRequest {
    #[serde(rename = "process_instance_id")]
    pub process_instance_id: String,
    #[serde(rename = "file_id")]
    pub file_id: String,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct ApprovalAttachmentDownloadUrlResponse {
    #[serde(default)]
    pub result: ApprovalAttachmentDownloadUrlResult,
}

impl fmt::Debug for ApprovalAttachmentDownloadUrlResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovalAttachmentDownloadUrlResponse")
            .field("result", &self.result)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct ApprovalAttachmentDownloadUrlResult {
    #[serde(
        rename = "download_url",
        alias = "downloadUrl",
        alias = "download_uri",
        alias = "downloadUri",
        alias = "url",
        default
    )]
    pub download_url: Option<String>,
    #[serde(default)]
    pub expiration: Option<i64>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl fmt::Debug for ApprovalAttachmentDownloadUrlResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovalAttachmentDownloadUrlResult")
            .field(
                "download_url",
                &self.download_url.as_ref().map(|_| REDACTED),
            )
            .field("expiration", &self.expiration)
            .field("extra", &REDACTED)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct HolidayTypeListRequest {
    #[serde(rename = "op_userid", skip_serializing_if = "Option::is_none")]
    pub op_user_id: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct HolidayTypeListResponse {
    #[serde(default, deserialize_with = "deserialize_holiday_type_list_result")]
    pub result: HolidayTypeListResult,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct HolidayTypeListResult {
    #[serde(default, alias = "leave_types", alias = "leaveTypes")]
    pub list: Vec<HolidayType>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct HolidayType {
    #[serde(rename = "leave_code", alias = "leaveCode", alias = "id", default)]
    pub leave_code: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(rename = "biz_type", alias = "bizType", default)]
    pub biz_type: Option<String>,
    #[serde(default)]
    pub unit: Option<String>,
    #[serde(rename = "hours_in_per_day", alias = "hoursInPerDay", default)]
    pub hours_in_per_day: Option<f64>,
    #[serde(rename = "natural_day_leave", alias = "naturalDayLeave", default)]
    pub natural_day_leave: Option<bool>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

fn deserialize_holiday_type_list_result<'de, D>(
    deserializer: D,
) -> std::result::Result<HolidayTypeListResult, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Payload {
        List(Vec<HolidayType>),
        Object(HolidayTypeListResult),
    }

    match Payload::deserialize(deserializer)? {
        Payload::List(list) => Ok(HolidayTypeListResult {
            list,
            ..HolidayTypeListResult::default()
        }),
        Payload::Object(result) => Ok(result),
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct AttendanceGroupListRequest {
    #[serde(rename = "op_user_id", skip_serializing_if = "Option::is_none")]
    pub op_user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct AttendanceGroupListResponse {
    #[serde(default, deserialize_with = "deserialize_attendance_group_list_result")]
    pub result: AttendanceGroupListResult,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct AttendanceGroupListResult {
    #[serde(default, alias = "groups")]
    pub list: Vec<AttendanceGroupSummary>,
    #[serde(rename = "has_more", alias = "hasMore", default)]
    pub has_more: bool,
    #[serde(rename = "next_cursor", alias = "nextCursor", default)]
    pub next_cursor: Option<u64>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct AttendanceGroupSummary {
    #[serde(rename = "group_id", alias = "groupId", alias = "id", default)]
    pub group_id: Option<i64>,
    #[serde(rename = "group_name", alias = "groupName", alias = "name", default)]
    pub group_name: Option<String>,
    #[serde(default)]
    pub r#type: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

fn deserialize_attendance_group_list_result<'de, D>(
    deserializer: D,
) -> std::result::Result<AttendanceGroupListResult, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Payload {
        List(Vec<AttendanceGroupSummary>),
        Object(AttendanceGroupListResult),
    }

    match Payload::deserialize(deserializer)? {
        Payload::List(list) => Ok(AttendanceGroupListResult {
            list,
            ..AttendanceGroupListResult::default()
        }),
        Payload::Object(result) => Ok(result),
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AttendanceGroupGetRequest {
    #[serde(rename = "group_id")]
    pub group_id: i64,
    #[serde(rename = "op_user_id", skip_serializing_if = "Option::is_none")]
    pub op_user_id: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct AttendanceGroupGetResponse {
    #[serde(default)]
    pub result: AttendanceGroupDetail,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct AttendanceGroupDetail {
    #[serde(rename = "group_id", alias = "groupId", alias = "id", default)]
    pub group_id: Option<i64>,
    #[serde(rename = "group_name", alias = "groupName", alias = "name", default)]
    pub group_name: Option<String>,
    #[serde(rename = "member_count", alias = "memberCount", default)]
    pub member_count: Option<u64>,
    #[serde(rename = "manager_user_ids", alias = "managerUserIds", default)]
    pub manager_user_ids: Vec<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct ApprovalOperationRecord {
    #[serde(rename = "userId", default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub date: Option<String>,
    #[serde(default)]
    pub r#type: Option<String>,
    #[serde(default)]
    pub result: Option<String>,
    #[serde(default)]
    pub remark: Option<String>,
    #[serde(default)]
    pub attachments: Vec<ApprovalAttachment>,
    #[serde(rename = "ccUserIds", default)]
    pub cc_user_ids: Vec<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct ApprovalAttachment {
    #[serde(rename = "fileName", default)]
    pub file_name: Option<String>,
    #[serde(rename = "fileSize", default)]
    pub file_size: Option<String>,
    #[serde(rename = "fileId", default)]
    pub file_id: Option<String>,
    #[serde(rename = "fileType", default)]
    pub file_type: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct ApprovalTask {
    #[serde(rename = "taskId", default)]
    pub task_id: Option<i64>,
    #[serde(rename = "userId", default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub result: Option<String>,
    #[serde(rename = "createTime", default)]
    pub create_time: Option<String>,
    #[serde(rename = "finishTime", default)]
    pub finish_time: Option<String>,
    #[serde(rename = "mobileUrl", default)]
    pub mobile_url: Option<String>,
    #[serde(rename = "pcUrl", default)]
    pub pc_url: Option<String>,
    #[serde(rename = "processInstanceId", default)]
    pub process_instance_id: Option<String>,
    #[serde(rename = "activityId", default)]
    pub activity_id: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DingTalkBoundaryErrorKind {
    InvalidUrl,
    EndpointPolicy,
    TransportPolicy,
    ClientBuild,
    Transport,
    ResponseDecode,
    HttpStatus,
    Api,
    Oapi,
}

impl DingTalkBoundaryErrorKind {
    const fn code(self) -> &'static str {
        match self {
            Self::InvalidUrl => "dingtalk_invalid_url",
            Self::EndpointPolicy => "dingtalk_endpoint_policy_violation",
            Self::TransportPolicy => "dingtalk_transport_policy_violation",
            Self::ClientBuild => "dingtalk_client_build_failed",
            Self::Transport => "dingtalk_transport_failed",
            Self::ResponseDecode => "dingtalk_response_decode_failed",
            Self::HttpStatus => "dingtalk_http_status_error",
            Self::Api => "dingtalk_api_error",
            Self::Oapi => "dingtalk_oapi_error",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DingTalkBoundaryError {
    kind: DingTalkBoundaryErrorKind,
    http_status: Option<u16>,
    provider_code: Option<i64>,
    retryable: bool,
}

impl DingTalkBoundaryError {
    const fn new(kind: DingTalkBoundaryErrorKind, retryable: bool) -> Self {
        Self {
            kind,
            http_status: None,
            provider_code: None,
            retryable,
        }
    }

    fn from_transport(error: &reqwest::Error) -> Self {
        Self::new(
            DingTalkBoundaryErrorKind::Transport,
            error.is_timeout() || error.is_connect(),
        )
    }

    fn from_http_status(status: reqwest::StatusCode) -> Self {
        let retryable = status == reqwest::StatusCode::REQUEST_TIMEOUT
            || status == reqwest::StatusCode::TOO_MANY_REQUESTS
            || status.is_server_error();
        Self {
            kind: DingTalkBoundaryErrorKind::HttpStatus,
            http_status: Some(status.as_u16()),
            provider_code: None,
            retryable,
        }
    }

    const fn from_provider_code(provider_code: i64) -> Self {
        Self {
            kind: DingTalkBoundaryErrorKind::Oapi,
            http_status: None,
            provider_code: Some(provider_code),
            retryable: false,
        }
    }

    fn into_service_error(self) -> ServiceError {
        let message = match (self.http_status, self.provider_code) {
            (Some(status), None) => format!(
                "kind={} status={status} retryable={}",
                self.kind.code(),
                self.retryable
            ),
            (None, Some(provider_code)) => format!(
                "kind={} provider_code={provider_code} retryable={}",
                self.kind.code(),
                self.retryable
            ),
            (None, None) => format!("kind={} retryable={}", self.kind.code(), self.retryable),
            (Some(_), Some(_)) => "kind=dingtalk_boundary_error retryable=false".to_owned(),
        };

        if matches!(
            self.kind,
            DingTalkBoundaryErrorKind::InvalidUrl
                | DingTalkBoundaryErrorKind::EndpointPolicy
                | DingTalkBoundaryErrorKind::TransportPolicy
        ) {
            ServiceError::bad_request(message)
        } else {
            ServiceError::service_unavailable(message)
        }
    }
}

#[derive(Deserialize)]
struct ApiEnvelope<T> {
    #[serde(default)]
    success: Option<ApiSuccess>,
    #[serde(flatten)]
    data: T,
}

impl<T> ApiEnvelope<T> {
    fn into_result(self) -> Result<T> {
        if self.success.as_ref().is_none_or(ApiSuccess::is_success) {
            Ok(self.data)
        } else {
            Err(
                DingTalkBoundaryError::new(DingTalkBoundaryErrorKind::Api, false)
                    .into_service_error(),
            )
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ApiSuccess {
    Bool(bool),
    String(String),
}

impl ApiSuccess {
    fn is_success(&self) -> bool {
        match self {
            Self::Bool(success) => *success,
            Self::String(success) => success.eq_ignore_ascii_case("true"),
        }
    }
}

#[derive(Deserialize)]
struct OapiEnvelope<T> {
    #[serde(default)]
    errcode: i64,
    #[serde(default, rename = "errmsg")]
    _provider_message: String,
    #[serde(flatten)]
    data: T,
}

impl<T> OapiEnvelope<T> {
    fn into_result(self) -> Result<T> {
        if self.errcode == 0 {
            Ok(self.data)
        } else {
            Err(DingTalkBoundaryError::from_provider_code(self.errcode).into_service_error())
        }
    }
}

fn default_api_base() -> String {
    DEFAULT_API_BASE.to_string()
}

fn default_oapi_base() -> String {
    DEFAULT_OAPI_BASE.to_string()
}

impl DingTalkEndpointPolicy {
    fn validate_bases(&self, api_base: &Url, oapi_base: &Url) -> Result<()> {
        let allowed = match self {
            Self::OfficialOnly => {
                let official_api = validate_endpoint_base(DEFAULT_API_BASE)?;
                let official_oapi = validate_endpoint_base(DEFAULT_OAPI_BASE)?;
                api_base == &official_api && oapi_base == &official_oapi
            }
            Self::TrustedOrigins {
                api_origin,
                oapi_origin,
            } => {
                let trusted_api = validate_trusted_origin(api_origin)?;
                let trusted_oapi = validate_trusted_origin(oapi_origin)?;
                same_origin(api_base, &trusted_api) && same_origin(oapi_base, &trusted_oapi)
            }
        };

        if allowed {
            Ok(())
        } else {
            Err(endpoint_policy_error())
        }
    }
}

fn validate_endpoint_base(raw: &str) -> Result<Url> {
    let raw_authority =
        raw_endpoint_authority_if_unambiguous(raw).ok_or_else(endpoint_policy_error)?;

    let mut url = Url::parse(raw).map_err(|_| {
        DingTalkBoundaryError::new(DingTalkBoundaryErrorKind::InvalidUrl, false)
            .into_service_error()
    })?;
    let structurally_safe = url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && route_path_is_unambiguous(url.path(), true)
        && url.origin().ascii_serialization() == format!("https://{raw_authority}");
    if !structurally_safe {
        return Err(endpoint_policy_error());
    }

    let path = url.path().trim_end_matches('/');
    let normalized_path = if path.is_empty() {
        "/".to_owned()
    } else {
        format!("{path}/")
    };
    url.set_path(&normalized_path);
    Ok(url)
}

fn validate_trusted_origin(raw: &str) -> Result<Url> {
    let origin = validate_endpoint_base(raw)?;
    if origin.path() == "/" {
        Ok(origin)
    } else {
        Err(endpoint_policy_error())
    }
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn endpoint_policy_error() -> ServiceError {
    DingTalkBoundaryError::new(DingTalkBoundaryErrorKind::EndpointPolicy, false)
        .into_service_error()
}

fn raw_endpoint_authority_if_unambiguous(raw: &str) -> Option<&str> {
    if raw.len() > MAX_ENDPOINT_BYTES
        || !raw.is_ascii()
        || raw != raw.trim()
        || raw
            .bytes()
            .any(|byte| byte <= b' ' || byte == 0x7f || matches!(byte, b'%' | b'\\'))
    {
        return None;
    }

    let authority_and_path = raw.strip_prefix("https://")?;
    let authority_end = authority_and_path
        .find(['/', '?', '#'])
        .unwrap_or(authority_and_path.len());
    let authority = &authority_and_path[..authority_end];
    if authority.is_empty() || authority.contains('@') || authority.ends_with(':') {
        return None;
    }
    let raw_path = if authority_and_path.as_bytes().get(authority_end) == Some(&b'/') {
        &authority_and_path[authority_end..]
    } else {
        "/"
    };
    route_path_is_unambiguous(raw_path, true).then_some(authority)
}

fn route_path_is_unambiguous(path: &str, root_allowed: bool) -> bool {
    if path == "/" {
        return root_allowed;
    }

    let relative_path = path.strip_prefix('/').unwrap_or(path);
    let relative_path = relative_path.strip_suffix('/').unwrap_or(relative_path);
    !relative_path.is_empty()
        && relative_path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.'))
        && relative_path
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

fn join_url(base: &Url, path: &str) -> Result<Url> {
    if !route_path_is_unambiguous(path, false) || Url::parse(path).is_ok() {
        return Err(endpoint_policy_error());
    }

    let relative_path = path.strip_prefix('/').unwrap_or(path);
    let url = base.join(relative_path).map_err(|_| {
        DingTalkBoundaryError::new(DingTalkBoundaryErrorKind::InvalidUrl, false)
            .into_service_error()
    })?;
    if same_origin(base, &url)
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && url.path().starts_with(base.path())
    {
        Ok(url)
    } else {
        Err(endpoint_policy_error())
    }
}

fn build_http_client(policy: DingTalkTransportPolicy) -> Result<reqwest::Client> {
    build_http_client_inner(policy, true)
}

fn build_http_client_inner(
    policy: DingTalkTransportPolicy,
    https_only: bool,
) -> Result<reqwest::Client> {
    policy.validate()?;
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(policy.connect_timeout())
        .timeout(policy.request_timeout())
        .read_timeout(policy.read_timeout())
        .https_only(https_only)
        .no_proxy()
        .build()
        .map_err(|_| {
            DingTalkBoundaryError::new(DingTalkBoundaryErrorKind::ClientBuild, false)
                .into_service_error()
        })
}

#[cfg(test)]
fn build_http_client_for_loopback_test(policy: DingTalkTransportPolicy) -> Result<reqwest::Client> {
    build_http_client_inner(policy, false)
}

fn map_transport_error(error: reqwest::Error) -> ServiceError {
    DingTalkBoundaryError::from_transport(&error).into_service_error()
}

fn map_decode_error(_error: reqwest::Error) -> ServiceError {
    response_decode_error()
}

async fn decode_bounded_json<T>(mut response: reqwest::Response, limit: usize) -> Result<T>
where
    T: DeserializeOwned,
{
    if response
        .content_length()
        .is_some_and(|content_length| content_length > limit as u64)
    {
        return Err(response_decode_error());
    }

    let capacity = response
        .content_length()
        .map_or(0, |content_length| content_length as usize);
    let mut body = Vec::with_capacity(capacity);
    while let Some(chunk) = response.chunk().await.map_err(map_decode_error)? {
        if chunk.len() > limit.saturating_sub(body.len()) {
            return Err(response_decode_error());
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| response_decode_error())
}

trait DingTalkResponseExt {
    async fn ensure_success(self) -> Result<reqwest::Response>;
}

impl DingTalkResponseExt for reqwest::Response {
    async fn ensure_success(self) -> Result<reqwest::Response> {
        let status = self.status();
        if status.is_success() {
            return Ok(self);
        }

        Err(DingTalkBoundaryError::from_http_status(status).into_service_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_approval_instance_ids_response() {
        let json = r#"{
            "result": {
                "list": ["id-1", "id-2"],
                "nextToken": "cursor-2"
            },
            "success": true
        }"#;

        let envelope: ApiEnvelope<ApprovalInstanceIdListApiResponse> =
            serde_json::from_str(json).expect("approval ids response should decode");
        let response = envelope.into_result().expect("api response should succeed");

        assert_eq!(response.result.list, ["id-1", "id-2"]);
        assert_eq!(response.result.next_token.as_deref(), Some("cursor-2"));
    }

    #[test]
    fn decodes_approval_instance_detail_response() {
        let json = r#"{
            "result": {
                "title": "请假",
                "originatorUserId": "user-1",
                "status": "COMPLETED",
                "result": "agree",
                "formComponentValues": [
                    {
                        "name": "请假类型",
                        "value": "病假",
                        "componentType": "TextField"
                    }
                ]
            },
            "success": "true"
        }"#;

        let envelope: ApiEnvelope<ApprovalProcessInstanceApiResponse> =
            serde_json::from_str(json).expect("approval detail response should decode");
        let response = envelope.into_result().expect("api response should succeed");

        assert_eq!(response.result.title.as_deref(), Some("请假"));
        assert_eq!(
            response.result.originator_user_id.as_deref(),
            Some("user-1")
        );
        assert_eq!(response.result.form_component_values.len(), 1);
        assert_eq!(
            response.result.form_component_values[0].value.as_deref(),
            Some("病假")
        );
    }

    #[test]
    fn returns_error_when_api_success_is_false() {
        let json = r#"{
            "result": {
                "list": []
            },
            "success": false
        }"#;

        let envelope: ApiEnvelope<ApprovalInstanceIdListApiResponse> =
            serde_json::from_str(json).expect("api envelope should decode");

        assert!(envelope.into_result().is_err());
    }

    #[test]
    fn access_token_response_validation_is_bounded_and_canonical() {
        let invalid = [
            AccessTokenResponse {
                access_token: String::new(),
                expire_in: 7200,
            },
            AccessTokenResponse {
                access_token: " ACCESS_TOKEN_987".to_owned(),
                expire_in: 7200,
            },
            AccessTokenResponse {
                access_token: "ACCESS_TOKEN_987\n".to_owned(),
                expire_in: 7200,
            },
            AccessTokenResponse {
                access_token: "访问令牌".to_owned(),
                expire_in: 7200,
            },
            AccessTokenResponse {
                access_token: "A".repeat(MAX_ACCESS_TOKEN_BYTES + 1),
                expire_in: 7200,
            },
            AccessTokenResponse {
                access_token: "ACCESS_TOKEN_987".to_owned(),
                expire_in: 0,
            },
            AccessTokenResponse {
                access_token: "ACCESS_TOKEN_987".to_owned(),
                expire_in: MAX_ACCESS_TOKEN_TTL_SECONDS + 1,
            },
        ];
        for response in invalid {
            let error = match response.into_validated() {
                Ok(_) => panic!("invalid token response must fail closed"),
                Err(error) => error,
            };
            let rendered = format!("{error:?} {error}");
            assert_no_sentinel(&rendered);
            assert!(rendered.contains("dingtalk_response_decode_failed"));
        }

        let short_lived = AccessTokenResponse {
            access_token: "SHORT_LIVED_TOKEN_987".to_owned(),
            expire_in: TOKEN_CACHE_SAFETY_MARGIN_SECONDS,
        }
        .into_validated()
        .expect("valid short-lived token");
        assert!(short_lived.cached.is_none());
    }

    fn sentinel_config() -> DingTalkConfig {
        DingTalkConfig {
            corp_id: Some("CORP_PRIVATE_987".to_owned()),
            app_id: Some("APP_PRIVATE_987".to_owned()),
            agent_id: Some("AGENT_PRIVATE_987".to_owned()),
            app_key: "APP_KEY_SECRET_987".to_owned(),
            app_secret: "APP_SECRET_987".to_owned(),
            callback_token: Some("CALLBACK_TOKEN_987".to_owned()),
            api_base: "https://api-private-987.example".to_owned(),
            oapi_base: "https://oapi-private-987.example".to_owned(),
        }
    }

    fn assert_no_sentinel(rendered: &str) {
        for sentinel in [
            "CORP_PRIVATE_987",
            "APP_PRIVATE_987",
            "AGENT_PRIVATE_987",
            "APP_KEY_SECRET_987",
            "APP_SECRET_987",
            "CALLBACK_TOKEN_987",
            "api-private-987",
            "oapi-private-987",
            "ACCESS_TOKEN_987",
            "PROVIDER_BODY_987",
            "PROVIDER_MESSAGE_987",
            "SIGNED_URL_TOKEN_987",
            "INVALID_URL_SECRET_987",
        ] {
            assert!(
                !rendered.contains(sentinel),
                "sensitive sentinel leaked: {sentinel}"
            );
        }
    }

    async fn one_shot_http_response(status: &str, body: &str) -> Url {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind one-shot HTTP listener");
        let address = listener.local_addr().expect("one-shot listener address");
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept HTTP request");
            let mut request = [0_u8; 4096];
            let _ = socket.read(&mut request).await;
            socket
                .write_all(response.as_bytes())
                .await
                .expect("write one-shot HTTP response");
        });

        Url::parse(&format!("http://{address}/provider")).expect("one-shot HTTP response URL")
    }

    #[test]
    fn config_debug_redacts_every_sensitive_value() {
        let rendered = format!("{:?}", sentinel_config());

        assert_no_sentinel(&rendered);
        assert!(rendered.contains("DingTalkConfig"));
        assert!(rendered.contains("[REDACTED]"));
    }

    #[tokio::test]
    async fn client_and_token_debug_redact_credentials_and_cached_tokens() {
        let client = DingTalkClient::new(DingTalkConfig {
            api_base: DEFAULT_API_BASE.to_owned(),
            oapi_base: DEFAULT_OAPI_BASE.to_owned(),
            ..sentinel_config()
        })
        .expect("valid client config");
        client
            .token_refresh
            .state
            .lock()
            .expect("token state")
            .cached = Some(CachedToken {
            value: "ACCESS_TOKEN_987".to_owned(),
            expires_at: Utc::now() + ChronoDuration::minutes(10),
        });
        let request = AccessTokenRequest {
            app_key: "APP_KEY_SECRET_987".to_owned(),
            app_secret: "APP_SECRET_987".to_owned(),
        };
        let response = AccessTokenResponse {
            access_token: "ACCESS_TOKEN_987".to_owned(),
            expire_in: 3600,
        };

        let cached_token = format!(
            "{:?}",
            client
                .token_refresh
                .state
                .lock()
                .expect("token state")
                .cached
                .as_ref()
        );
        for rendered in [
            format!("{client:?}"),
            cached_token,
            format!("{request:?}"),
            format!("{response:?}"),
        ] {
            assert_no_sentinel(&rendered);
            assert!(rendered.contains("[REDACTED]"));
        }
    }

    #[tokio::test]
    async fn transport_and_decode_errors_never_echo_request_urls() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind disconnect listener");
        let address = listener.local_addr().expect("disconnect listener address");
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept request");
            drop(socket);
        });
        let transport_url = Url::parse(&format!(
            "http://{address}/provider?access_token=SIGNED_URL_TOKEN_987"
        ))
        .expect("transport URL");
        let transport = reqwest::Client::new()
            .get(transport_url)
            .send()
            .await
            .expect_err("closed connection must fail");

        let mut decode_url = one_shot_http_response("200 OK", "not-json").await;
        decode_url
            .query_pairs_mut()
            .append_pair("access_token", "SIGNED_URL_TOKEN_987");
        let decode = reqwest::Client::new()
            .get(decode_url)
            .send()
            .await
            .expect("decode response")
            .json::<serde_json::Value>()
            .await
            .expect_err("invalid JSON must fail");

        for error in [map_transport_error(transport), map_decode_error(decode)] {
            let rendered = format!("{error:?} {error}");
            assert_no_sentinel(&rendered);
        }
    }

    #[tokio::test]
    async fn bounded_json_decode_rejects_declared_and_chunked_overflow_immediately() {
        use tokio::io::AsyncWriteExt;
        use tokio::time::{Duration as TokioDuration, timeout};

        for response_head in [
            "HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\n".to_owned(),
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n11\r\nAAAAAAAAAAAAAAAAA\r\n"
                .to_owned(),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind oversized response provider");
            let address = listener.local_addr().expect("oversized provider address");
            let provider = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.expect("accept decode request");
                socket
                    .write_all(response_head.as_bytes())
                    .await
                    .expect("write oversized response prefix");
                tokio::time::sleep(TokioDuration::from_secs(2)).await;
            });

            let response = reqwest::Client::new()
                .get(format!("http://{address}/bounded-json"))
                .send()
                .await
                .expect("receive oversized response headers");
            let error = timeout(
                TokioDuration::from_millis(200),
                decode_bounded_json::<serde_json::Value>(response, 16),
            )
            .await
            .expect("decoder must reject before the provider finishes")
            .expect_err("oversized response must fail");
            let rendered = format!("{error:?} {error}");
            assert_no_sentinel(&rendered);
            assert!(rendered.contains("dingtalk_response_decode_failed"));
            provider.abort();
        }
    }

    #[tokio::test]
    async fn http_status_error_never_echoes_provider_body() {
        let url = one_shot_http_response("502 Bad Gateway", "PROVIDER_BODY_987").await;
        let response = reqwest::Client::new()
            .get(url)
            .send()
            .await
            .expect("HTTP status response");

        let error = response
            .ensure_success()
            .await
            .expect_err("non-success response must fail");
        let rendered = format!("{error:?} {error}");

        assert_no_sentinel(&rendered);
        assert!(rendered.contains("502"));
    }

    #[test]
    fn oapi_error_never_echoes_provider_message() {
        let envelope = OapiEnvelope {
            errcode: 40_001,
            _provider_message: "PROVIDER_MESSAGE_987".to_owned(),
            data: (),
        };

        let error = envelope.into_result().expect_err("OAPI failure");
        let rendered = format!("{error:?} {error}");

        assert_no_sentinel(&rendered);
        assert!(rendered.contains("40001"));
    }

    #[test]
    fn invalid_url_error_never_echoes_config_or_path() {
        let error = validate_endpoint_base("https://[INVALID_URL_SECRET_987")
            .expect_err("invalid URL must fail");
        let rendered = format!("{error:?} {error}");

        assert_no_sentinel(&rendered);
    }

    #[test]
    fn endpoint_policy_rejects_untrusted_or_ambiguous_origins_before_io() {
        let official = DingTalkConfig {
            api_base: DEFAULT_API_BASE.to_owned(),
            oapi_base: DEFAULT_OAPI_BASE.to_owned(),
            ..sentinel_config()
        };

        for (field, value) in [
            ("api", "http://api.dingtalk.com"),
            ("api", "https://api.dingtalk.com.attacker-987.example"),
            ("api", "https://APP_SECRET_987@api.dingtalk.com"),
            ("api", "https://api.dingtalk.com?token=APP_SECRET_987"),
            ("api", "https://api.dingtalk.com#APP_SECRET_987"),
            ("api", "https://api.dingtalk.com/%2e%2e/private"),
            ("api", "https://api.dingtalk.com/private%2fescape"),
            ("api", "https:///api.dingtalk.com"),
            ("api", "https://api.\ndingtalk.com"),
            ("api", "https://api.\rdingtalk.com"),
            ("api", "https://api.\tdingtalk.com"),
            ("api", "https://api．dingtalk.com"),
            ("api", "https://@api.dingtalk.com"),
            ("api", "https://api.dingtalk.com:"),
            ("api", "https://api.dingtalk.com:/"),
            ("api", "https://API.DINGTALK.COM"),
            ("api", "https://api.dingtalk.com:443"),
            ("api", "https://api.dingtalk.com:0443"),
            ("oapi", "https:///oapi.dingtalk.com"),
            ("oapi", "https://@oapi.dingtalk.com"),
            ("oapi", "https://oapi.dingtalk.com.attacker-987.example"),
        ] {
            let mut config = official.clone();
            if field == "api" {
                config.api_base = value.to_owned();
            } else {
                config.oapi_base = value.to_owned();
            }

            let error = DingTalkClient::new(config).expect_err("origin must be rejected");
            let rendered = format!("{error:?} {error}");
            assert_no_sentinel(&rendered);
            assert!(rendered.contains("dingtalk_endpoint_policy_violation"));
        }
    }

    #[test]
    fn trusted_endpoint_authority_cannot_be_recovered_from_a_raw_path() {
        let config = DingTalkConfig {
            api_base: "https:///api.private.example/dingtalk".to_owned(),
            oapi_base: "https://oapi.private.example/dingtalk".to_owned(),
            ..sentinel_config()
        };
        let policy = DingTalkEndpointPolicy::TrustedOrigins {
            api_origin: "https://api.private.example".to_owned(),
            oapi_origin: "https://oapi.private.example".to_owned(),
        };

        let error = DingTalkClient::with_endpoint_policy(config, policy)
            .expect_err("raw endpoint authority must be non-empty");
        let rendered = format!("{error:?} {error}");
        assert_no_sentinel(&rendered);
        assert!(rendered.contains("dingtalk_endpoint_policy_violation"));
    }

    #[test]
    fn trusted_origin_policy_is_explicit_and_purpose_bound() {
        let config = DingTalkConfig {
            api_base: "https://api.private-987.example/dingtalk".to_owned(),
            oapi_base: "https://oapi.private-987.example/dingtalk".to_owned(),
            ..sentinel_config()
        };
        let policy = DingTalkEndpointPolicy::TrustedOrigins {
            api_origin: "https://api.private-987.example".to_owned(),
            oapi_origin: "https://oapi.private-987.example".to_owned(),
        };

        let client = DingTalkClient::with_endpoint_policy(config.clone(), policy.clone())
            .expect("explicit trusted origins must be accepted");
        assert_eq!(
            client
                .api_url("/v1.0/oauth2/accessToken")
                .expect("trusted API URL")
                .as_str(),
            "https://api.private-987.example/dingtalk/v1.0/oauth2/accessToken"
        );

        let swapped = DingTalkEndpointPolicy::TrustedOrigins {
            api_origin: "https://oapi.private-987.example".to_owned(),
            oapi_origin: "https://api.private-987.example".to_owned(),
        };
        let error = DingTalkClient::with_endpoint_policy(config, swapped)
            .expect_err("purpose-swapped origins must fail");
        let rendered = format!("{policy:?} {error:?} {error}");
        assert_no_sentinel(&rendered);
        assert!(rendered.contains("dingtalk_endpoint_policy_violation"));

        let port_config = DingTalkConfig {
            api_base: "https://api.private.example:8443/dingtalk".to_owned(),
            oapi_base: "https://oapi.private.example:9443/dingtalk".to_owned(),
            ..sentinel_config()
        };
        let port_policy = DingTalkEndpointPolicy::TrustedOrigins {
            api_origin: "https://api.private.example:8443".to_owned(),
            oapi_origin: "https://oapi.private.example:9443".to_owned(),
        };
        DingTalkClient::with_endpoint_policy(port_config, port_policy)
            .expect("canonical non-default trusted ports must be accepted");
    }

    #[test]
    fn trusted_base_rejects_raw_dot_segments_before_url_normalization() {
        let policy = DingTalkEndpointPolicy::TrustedOrigins {
            api_origin: "https://api.private.example".to_owned(),
            oapi_origin: "https://oapi.private.example".to_owned(),
        };

        for api_base in [
            "https://api.private.example/dingtalk/../capture",
            "https://api.private.example/dingtalk/./capture",
            "https://api.private.example/a/../../capture",
        ] {
            let config = DingTalkConfig {
                api_base: api_base.to_owned(),
                oapi_base: "https://oapi.private.example/dingtalk".to_owned(),
                ..sentinel_config()
            };
            let error = DingTalkClient::with_endpoint_policy(config, policy.clone())
                .expect_err("raw base dot segments must fail before URL normalization");
            let rendered = format!("{error:?} {error}");
            assert_no_sentinel(&rendered);
            assert!(rendered.contains("dingtalk_endpoint_policy_violation"));
        }
    }

    #[test]
    fn request_path_cannot_escape_the_validated_origin() {
        let base = validate_endpoint_base("https://api.private.example/dingtalk")
            .expect("trusted API base");
        for path in [
            "https://api.private.example/dingtalk/capture?token=SIGNED_URL_TOKEN_987",
            "//path-escape-987.example/capture",
            "../capture",
            "a/../../capture",
            "%2e%2e/capture",
            "%2E%2E/capture",
            ".%2e/capture",
            "%2e./capture",
        ] {
            let error = join_url(&base, path)
                .expect_err("request path must remain relative and inside its purpose base");
            let rendered = format!("{error:?} {error}");

            assert_no_sentinel(&rendered);
            assert!(rendered.contains("dingtalk_endpoint_policy_violation"));
        }
    }

    #[tokio::test]
    async fn production_redirect_policy_never_follows_cross_origin_redirects() {
        use tokio::time::{Duration as TokioDuration, timeout};

        for status in [
            "302 Found",
            "307 Temporary Redirect",
            "308 Permanent Redirect",
        ] {
            let target = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind redirect target");
            let target_address = target.local_addr().expect("redirect target address");
            let source = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind redirect source");
            let source_address = source.local_addr().expect("redirect source address");
            let response = format!(
                "HTTP/1.1 {status}\r\nLocation: http://{target_address}/capture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};

                let (mut socket, _) = source.accept().await.expect("accept redirect request");
                let mut request = [0_u8; 4096];
                let _ = socket.read(&mut request).await;
                socket
                    .write_all(response.as_bytes())
                    .await
                    .expect("write redirect response");
            });

            let client = build_http_client_for_loopback_test(DingTalkTransportPolicy::default())
                .expect("build secure loopback client");
            let response = client
                .post(format!("http://{source_address}/oauth"))
                .header("x-acs-dingtalk-access-token", "ACCESS_TOKEN_987")
                .body("APP_SECRET_987")
                .send()
                .await
                .expect("receive redirect response without following it");

            assert!(response.status().is_redirection());
            assert!(
                timeout(TokioDuration::from_millis(200), target.accept())
                    .await
                    .is_err(),
                "redirect target unexpectedly received a request for {status}"
            );
        }
    }

    #[tokio::test]
    async fn hanging_token_refresh_is_bounded_and_returns_typed_retryable_timeout() {
        use tokio::time::{Duration as TokioDuration, timeout};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind hanging provider");
        let address = listener.local_addr().expect("hanging provider address");
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept token request");
            let _held_connection = socket;
            tokio::time::sleep(TokioDuration::from_secs(2)).await;
        });

        let policy = DingTalkTransportPolicy::new(
            std::time::Duration::from_millis(100),
            std::time::Duration::from_millis(250),
            std::time::Duration::from_millis(100),
        )
        .expect("valid bounded test transport policy");
        let api_base = Url::parse(&format!("http://{address}")).expect("loopback API base");
        let client = DingTalkClient {
            config: DingTalkConfig {
                api_base: api_base.to_string(),
                oapi_base: api_base.to_string(),
                ..sentinel_config()
            },
            api_base: api_base.clone(),
            oapi_base: api_base,
            http: build_http_client_for_loopback_test(policy)
                .expect("build bounded loopback client"),
            token_refresh: Arc::new(TokenRefreshCoordinator::new()),
            token_refresh_timeout: policy.request_timeout(),
        };

        let errors = timeout(TokioDuration::from_secs(1), async {
            let mut waiters = Vec::new();
            for _ in 0..16 {
                let client = client.clone();
                waiters.push(tokio::spawn(async move { client.access_token().await }));
            }

            let mut errors = Vec::new();
            for waiter in waiters {
                errors.push(
                    waiter
                        .await
                        .expect("token waiter task")
                        .expect_err("refresh must time out"),
                );
            }
            errors
        })
        .await
        .expect("all token waiters must share one fixed policy deadline");

        assert_eq!(errors.len(), 16);
        for error in errors {
            let rendered = format!("{error:?} {error}");
            assert_no_sentinel(&rendered);
            assert!(rendered.contains("dingtalk_transport_failed"));
            assert!(rendered.contains("retryable=true"));
        }
    }

    #[tokio::test]
    async fn concurrent_token_refresh_is_single_flight() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{Duration as TokioDuration, timeout};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind token provider");
        let address = listener.local_addr().expect("token provider address");
        let provider = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept token request");
            let mut request = [0_u8; 4096];
            let _ = socket.read(&mut request).await;
            tokio::time::sleep(TokioDuration::from_millis(100)).await;

            let body = r#"{"accessToken":"SHARED_ACCESS_TOKEN_987","expireIn":7200}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            socket
                .write_all(response.as_bytes())
                .await
                .expect("write token response");

            assert!(
                timeout(TokioDuration::from_millis(300), listener.accept())
                    .await
                    .is_err(),
                "concurrent waiters triggered more than one token request"
            );
        });

        let policy = DingTalkTransportPolicy::new(
            StdDuration::from_millis(100),
            StdDuration::from_secs(1),
            StdDuration::from_millis(500),
        )
        .expect("valid single-flight policy");
        let api_base = Url::parse(&format!("http://{address}")).expect("loopback API base");
        let client = DingTalkClient {
            config: DingTalkConfig {
                api_base: api_base.to_string(),
                oapi_base: api_base.to_string(),
                ..sentinel_config()
            },
            api_base: api_base.clone(),
            oapi_base: api_base,
            http: build_http_client_for_loopback_test(policy)
                .expect("build single-flight loopback client"),
            token_refresh: Arc::new(TokenRefreshCoordinator::new()),
            token_refresh_timeout: policy.request_timeout(),
        };

        let mut waiters = Vec::new();
        for _ in 0..16 {
            let client = client.clone();
            waiters.push(tokio::spawn(async move { client.access_token().await }));
        }
        for waiter in waiters {
            assert_eq!(
                waiter
                    .await
                    .expect("token waiter task")
                    .expect("shared token refresh"),
                "SHARED_ACCESS_TOKEN_987"
            );
        }
        provider.await.expect("token provider task");
    }

    #[tokio::test]
    async fn concurrent_token_refresh_shares_the_same_failure_result() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{Duration as TokioDuration, timeout};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind failing token provider");
        let address = listener.local_addr().expect("failing provider address");
        let provider = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept token request");
            let mut request = [0_u8; 4096];
            let _ = socket.read(&mut request).await;
            tokio::time::sleep(TokioDuration::from_millis(100)).await;
            socket
                .write_all(
                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("write token failure");

            assert!(
                timeout(TokioDuration::from_millis(300), listener.accept())
                    .await
                    .is_err(),
                "concurrent waiters retried an already completed refresh"
            );
        });

        let policy = DingTalkTransportPolicy::new(
            StdDuration::from_millis(100),
            StdDuration::from_secs(1),
            StdDuration::from_millis(500),
        )
        .expect("valid failure-sharing policy");
        let api_base = Url::parse(&format!("http://{address}")).expect("loopback API base");
        let client = DingTalkClient {
            config: DingTalkConfig {
                api_base: api_base.to_string(),
                oapi_base: api_base.to_string(),
                ..sentinel_config()
            },
            api_base: api_base.clone(),
            oapi_base: api_base,
            http: build_http_client_for_loopback_test(policy)
                .expect("build failure-sharing loopback client"),
            token_refresh: Arc::new(TokenRefreshCoordinator::new()),
            token_refresh_timeout: policy.request_timeout(),
        };

        let mut waiters = Vec::new();
        for _ in 0..16 {
            let client = client.clone();
            waiters.push(tokio::spawn(async move { client.access_token().await }));
        }
        for waiter in waiters {
            let error = waiter
                .await
                .expect("token waiter task")
                .expect_err("shared refresh must fail");
            let rendered = format!("{error:?} {error}");
            assert_no_sentinel(&rendered);
            assert!(
                rendered.contains("dingtalk_http_status_error"),
                "{rendered}"
            );
            assert!(rendered.contains("status=503"), "{rendered}");
            assert!(rendered.contains("retryable=true"), "{rendered}");
        }
        provider.await.expect("failing token provider task");
    }

    #[tokio::test]
    async fn malicious_token_ttl_fails_typed_and_the_next_generation_can_retry() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind TTL token provider");
        let address = listener.local_addr().expect("TTL provider address");
        let provider = tokio::spawn(async move {
            for body in [
                r#"{"accessToken":"ACCESS_TOKEN_987","expireIn":9223372036854775807}"#,
                r#"{"accessToken":"RECOVERED_ACCESS_TOKEN_987","expireIn":7200}"#,
            ] {
                let (mut socket, _) = listener.accept().await.expect("accept token request");
                let mut request = [0_u8; 4096];
                let _ = socket.read(&mut request).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket
                    .write_all(response.as_bytes())
                    .await
                    .expect("write token response");
            }
        });

        let policy = DingTalkTransportPolicy::new(
            StdDuration::from_millis(100),
            StdDuration::from_secs(1),
            StdDuration::from_millis(500),
        )
        .expect("valid TTL policy");
        let api_base = Url::parse(&format!("http://{address}")).expect("loopback API base");
        let client = DingTalkClient {
            config: DingTalkConfig {
                api_base: api_base.to_string(),
                oapi_base: api_base.to_string(),
                ..sentinel_config()
            },
            api_base: api_base.clone(),
            oapi_base: api_base,
            http: build_http_client_for_loopback_test(policy).expect("build TTL loopback client"),
            token_refresh: Arc::new(TokenRefreshCoordinator::new()),
            token_refresh_timeout: policy.request_timeout(),
        };

        let error = client
            .access_token()
            .await
            .expect_err("unbounded provider TTL must fail");
        let rendered = format!("{error:?} {error}");
        assert_no_sentinel(&rendered);
        assert!(rendered.contains("dingtalk_response_decode_failed"));

        assert_eq!(
            client.access_token().await.expect("next generation retry"),
            "RECOVERED_ACCESS_TOKEN_987"
        );
        provider.await.expect("TTL provider task");
    }

    #[tokio::test]
    async fn refresh_result_is_bound_to_one_immutable_generation() {
        let coordinator = TokenRefreshCoordinator::new();
        let first = match coordinator.acquire().expect("first generation") {
            TokenRefreshAction::Start(operation) => operation,
            _ => panic!("first generation must start"),
        };
        let delayed_waiter = match coordinator.acquire().expect("join first generation") {
            TokenRefreshAction::Join(operation) => operation,
            _ => panic!("concurrent caller must bind to first generation"),
        };
        assert!(Arc::ptr_eq(&first, &delayed_waiter));

        coordinator.complete(
            &first,
            Err(
                DingTalkBoundaryError::from_http_status(reqwest::StatusCode::SERVICE_UNAVAILABLE)
                    .into_service_error(),
            ),
        );
        let second = match coordinator.acquire().expect("second generation") {
            TokenRefreshAction::Start(operation) => operation,
            _ => panic!("new caller must be able to retry"),
        };
        coordinator.complete(
            &second,
            Ok(ValidatedAccessToken {
                value: "RECOVERED_ACCESS_TOKEN_987".to_owned(),
                cached: None,
            }),
        );

        assert_eq!(
            second.wait().await.expect("second generation result"),
            "RECOVERED_ACCESS_TOKEN_987"
        );
        let first_error = delayed_waiter
            .wait()
            .await
            .expect_err("delayed first-generation waiter must keep the first result");
        let rendered = format!("{first_error:?} {first_error}");
        assert!(rendered.contains("dingtalk_http_status_error"));
        assert!(rendered.contains("status=503"));
        assert!(rendered.contains("retryable=true"));
    }

    #[tokio::test]
    async fn starter_cancellation_does_not_cancel_the_shared_refresh() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{Duration as TokioDuration, timeout};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind cancellation provider");
        let address = listener
            .local_addr()
            .expect("cancellation provider address");
        let provider = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept token request");
            let mut request = [0_u8; 4096];
            let _ = socket.read(&mut request).await;
            tokio::time::sleep(TokioDuration::from_millis(150)).await;
            let body = r#"{"accessToken":"CANCELLATION_SAFE_TOKEN_987","expireIn":7200}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            socket
                .write_all(response.as_bytes())
                .await
                .expect("write token response");
            assert!(
                timeout(TokioDuration::from_millis(300), listener.accept())
                    .await
                    .is_err(),
                "starter cancellation triggered another refresh"
            );
        });

        let policy = DingTalkTransportPolicy::new(
            StdDuration::from_millis(100),
            StdDuration::from_secs(1),
            StdDuration::from_millis(500),
        )
        .expect("valid cancellation policy");
        let api_base = Url::parse(&format!("http://{address}")).expect("loopback API base");
        let client = DingTalkClient {
            config: DingTalkConfig {
                api_base: api_base.to_string(),
                oapi_base: api_base.to_string(),
                ..sentinel_config()
            },
            api_base: api_base.clone(),
            oapi_base: api_base,
            http: build_http_client_for_loopback_test(policy)
                .expect("build cancellation loopback client"),
            token_refresh: Arc::new(TokenRefreshCoordinator::new()),
            token_refresh_timeout: policy.request_timeout(),
        };

        assert!(
            timeout(TokioDuration::from_millis(50), client.access_token())
                .await
                .is_err(),
            "starter call should be cancelled by its caller"
        );
        assert_eq!(
            client.access_token().await.expect("join detached refresh"),
            "CANCELLATION_SAFE_TOKEN_987"
        );
        provider.await.expect("cancellation provider task");
    }

    #[tokio::test]
    async fn refresh_worker_panic_is_supervised_and_the_next_generation_can_retry() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind panic recovery provider");
        let address = listener.local_addr().expect("panic recovery address");
        let provider = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept retry request");
            let mut request = [0_u8; 4096];
            let _ = socket.read(&mut request).await;
            let body = r#"{"accessToken":"PANIC_RECOVERED_TOKEN_987","expireIn":7200}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            socket
                .write_all(response.as_bytes())
                .await
                .expect("write retry response");
        });

        let policy = DingTalkTransportPolicy::new(
            StdDuration::from_millis(100),
            StdDuration::from_secs(1),
            StdDuration::from_millis(500),
        )
        .expect("valid panic recovery policy");
        let api_base = Url::parse(&format!("http://{address}")).expect("loopback API base");
        let client = DingTalkClient {
            config: DingTalkConfig {
                api_base: api_base.to_string(),
                oapi_base: api_base.to_string(),
                ..sentinel_config()
            },
            api_base: api_base.clone(),
            oapi_base: api_base,
            http: build_http_client_for_loopback_test(policy)
                .expect("build panic recovery loopback client"),
            token_refresh: Arc::new(TokenRefreshCoordinator::new()),
            token_refresh_timeout: policy.request_timeout(),
        };

        let failed_operation = match client.token_refresh.acquire().expect("panic generation") {
            TokenRefreshAction::Start(operation) => operation,
            _ => panic!("panic generation must start"),
        };
        client.spawn_access_token_refresh_worker(failed_operation.clone(), async {
            panic!("provider-controlled refresh panic sentinel")
        });
        let error = failed_operation
            .wait()
            .await
            .expect_err("panic must become a typed failure");
        let rendered = format!("{error:?} {error}");
        assert!(rendered.contains("dingtalk_transport_failed"));
        assert!(rendered.contains("retryable=true"));

        assert_eq!(
            client
                .access_token()
                .await
                .expect("retry after supervised panic"),
            "PANIC_RECOVERED_TOKEN_987"
        );
        provider.await.expect("panic recovery provider task");
    }

    #[test]
    fn transport_policy_rejects_unbounded_or_incoherent_timeouts() {
        let cases = [
            (
                std::time::Duration::ZERO,
                std::time::Duration::from_secs(1),
                std::time::Duration::from_secs(1),
            ),
            (
                std::time::Duration::from_secs(2),
                std::time::Duration::from_secs(1),
                std::time::Duration::from_secs(1),
            ),
            (
                std::time::Duration::from_secs(1),
                std::time::Duration::from_secs(1),
                std::time::Duration::from_secs(2),
            ),
            (
                std::time::Duration::from_secs(1),
                std::time::Duration::from_secs(121),
                std::time::Duration::from_secs(1),
            ),
        ];

        for (connect, request, read) in cases {
            let error = DingTalkTransportPolicy::new(connect, request, read)
                .expect_err("unbounded transport policy must fail");
            let rendered = format!("{error:?} {error}");
            assert_no_sentinel(&rendered);
            assert!(rendered.contains("dingtalk_transport_policy_violation"));
        }
    }

    #[test]
    fn signed_url_debug_redacts_url_and_untrusted_provider_fields() {
        let mut extra = serde_json::Map::new();
        extra.insert(
            "provider_payload".to_owned(),
            serde_json::Value::String("PROVIDER_BODY_987".to_owned()),
        );
        let result = ApprovalAttachmentDownloadUrlResult {
            download_url: Some(
                "https://download.example/object?token=SIGNED_URL_TOKEN_987".to_owned(),
            ),
            expiration: Some(123_456),
            extra,
        };
        let response = ApprovalAttachmentDownloadUrlResponse {
            result: result.clone(),
        };

        for rendered in [format!("{result:?}"), format!("{response:?}")] {
            assert_no_sentinel(&rendered);
            assert!(rendered.contains("[REDACTED]"));
            assert!(rendered.contains("123456"));
        }
    }
}
