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

        let envelope: ApiEnvelope<R> = self
            .http
            .post(url)
            .header("x-acs-dingtalk-access-token", token)
            .json(body)
            .send()
            .await
            .map_err(map_transport_error)?
            .ensure_success()
            .await?
            .json()
            .await
            .map_err(map_decode_error)?;

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

        let envelope: ApiEnvelope<R> = self
            .http
            .get(url)
            .header("x-acs-dingtalk-access-token", token)
            .send()
            .await
            .map_err(map_transport_error)?
            .ensure_success()
            .await?
            .json()
            .await
            .map_err(map_decode_error)?;

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

        let envelope: OapiEnvelope<R> = self
            .http
            .post(url)
            .json(body)
            .send()
            .await
            .map_err(map_transport_error)?
            .ensure_success()
            .await?
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
            .ensure_success()
            .await?
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

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct DepartmentListRequest {
    #[serde(rename = "dept_id", skip_serializing_if = "Option::is_none")]
    pub dept_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct DepartmentListResponse {
    #[serde(default, deserialize_with = "deserialize_department_list_result")]
    pub result: DepartmentListResult,
}

pub type DepartmentListResult = Vec<DingTalkDepartment>;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct DepartmentUserListResponse {
    #[serde(default)]
    pub result: DepartmentUserListResult,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserGetRequest {
    pub userid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct UserGetResponse {
    #[serde(default)]
    pub result: DingTalkUser,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessCodeByNameRequest {
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
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

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ProcessCodeByNameResult {
    #[serde(rename = "process_code", alias = "processCode", default)]
    pub process_code: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessListByUserRequest {
    pub userid: String,
    pub offset: u64,
    pub size: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ProcessListByUserResponse {
    #[serde(default)]
    pub result: ProcessListByUserResult,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
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

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ApprovalInstanceIdListResponse {
    #[serde(default)]
    pub list: Vec<String>,
    #[serde(rename = "nextToken", default, skip_serializing_if = "Option::is_none")]
    pub next_token: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct ApprovalInstanceIdListApiResponse {
    result: ApprovalInstanceIdListResponse,
}

#[derive(Clone, Debug, Deserialize)]
struct ApprovalProcessInstanceApiResponse {
    result: ApprovalProcessInstance,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
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

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApprovalAttachmentDownloadUrlRequest {
    #[serde(rename = "process_instance_id")]
    pub process_instance_id: String,
    #[serde(rename = "file_id")]
    pub file_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ApprovalAttachmentDownloadUrlResponse {
    #[serde(default)]
    pub result: ApprovalAttachmentDownloadUrlResult,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
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

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct HolidayTypeListRequest {
    #[serde(rename = "op_userid", skip_serializing_if = "Option::is_none")]
    pub op_user_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct HolidayTypeListResponse {
    #[serde(default, deserialize_with = "deserialize_holiday_type_list_result")]
    pub result: HolidayTypeListResult,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct HolidayTypeListResult {
    #[serde(default, alias = "leave_types", alias = "leaveTypes")]
    pub list: Vec<HolidayType>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
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

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct AttendanceGroupListRequest {
    #[serde(rename = "op_user_id", skip_serializing_if = "Option::is_none")]
    pub op_user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct AttendanceGroupListResponse {
    #[serde(default, deserialize_with = "deserialize_attendance_group_list_result")]
    pub result: AttendanceGroupListResult,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
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

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttendanceGroupGetRequest {
    #[serde(rename = "group_id")]
    pub group_id: i64,
    #[serde(rename = "op_user_id", skip_serializing_if = "Option::is_none")]
    pub op_user_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct AttendanceGroupGetResponse {
    #[serde(default)]
    pub result: AttendanceGroupDetail,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
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

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
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

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
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

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
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

#[derive(Debug, Deserialize)]
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
            Err(ServiceError::service_unavailable("dingtalk api error"))
        }
    }
}

#[derive(Debug, Deserialize)]
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

fn map_decode_error(error: reqwest::Error) -> ServiceError {
    ServiceError::service_unavailable(format!("failed to decode dingtalk response: {error}"))
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

        let body = self
            .text()
            .await
            .unwrap_or_else(|error| format!("failed to read error body: {error}"));
        Err(ServiceError::service_unavailable(format!(
            "dingtalk http status error {status}: {body}"
        )))
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
}
