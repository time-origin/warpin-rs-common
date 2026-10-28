use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;
use warpin_errors::{ResultCode, ResultObject, SUCCESS, ServiceError};

pub type ApiResult<T> = Result<T, ApiError>;
pub type ServiceResult<T> = ResultEnvelope<T>;

#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct DeletePayload {
    pub id: Uuid,
    pub hard: bool,
    pub deleted: bool,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct FileOutputPayload {
    pub name: String,
    pub path: String,
    pub content_type: Option<String>,
    pub size_bytes: Option<u64>,
    pub download_url: Option<String>,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct ResultEnvelope<T> {
    pub code: ResultCode,
    pub data: Option<T>,
    pub count: u64,
    pub msg: String,
}

impl<T> ResultEnvelope<T> {
    pub fn success(data: T) -> Self {
        Self::from(ResultObject::success(data))
    }

    pub fn success_with_count(data: T, count: u64) -> Self {
        Self::from(ResultObject::success_with_count(data, count))
    }

    pub fn success_with_message(data: T, msg: impl Into<String>) -> Self {
        Self::from(ResultObject::success_with_message(data, msg))
    }

    pub fn failure(error: ServiceError) -> Self {
        Self::from(ResultObject::failure(error))
    }

    pub fn map_data<U, F>(self, f: F) -> ResultEnvelope<U>
    where
        F: FnOnce(T) -> U,
    {
        ResultEnvelope {
            code: self.code,
            count: self.count,
            msg: self.msg,
            data: self.data.map(f),
        }
    }
}

impl<T> From<ResultObject<T>> for ResultEnvelope<T> {
    fn from(result: ResultObject<T>) -> Self {
        Self {
            code: result.code,
            data: result.data,
            count: result.count,
            msg: result.msg,
        }
    }
}

impl<T> From<ServiceError> for ResultEnvelope<T> {
    fn from(error: ServiceError) -> Self {
        Self::failure(error)
    }
}

impl<T> IntoResponse for ResultEnvelope<T>
where
    T: Serialize,
{
    fn into_response(self) -> Response {
        let status = status_from_code(self.code);
        (status, Json(self)).into_response()
    }
}

#[derive(Debug, Clone)]
pub struct ApiError {
    error: ServiceError,
}

impl ApiError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self {
            error: ServiceError::bad_request(message),
        }
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            error: ServiceError::unauthorized(message),
        }
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self {
            error: ServiceError::forbidden(message),
        }
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self {
            error: ServiceError::not_found(message),
        }
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self {
            error: ServiceError::conflict(message),
        }
    }

    pub fn unprocessable_entity(message: impl Into<String>) -> Self {
        Self {
            error: ServiceError::unprocessable_entity(message),
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            error: ServiceError::internal(message),
        }
    }

    pub fn service_unavailable(message: impl Into<String>) -> Self {
        Self {
            error: ServiceError::service_unavailable(message),
        }
    }
}

impl From<ServiceError> for ApiError {
    fn from(error: ServiceError) -> Self {
        Self { error }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        ResultEnvelope::<()>::failure(self.error).into_response()
    }
}

fn status_from_code(code: ResultCode) -> StatusCode {
    match code {
        SUCCESS => StatusCode::OK,
        // Preserve HTTP errors, including conflict, validation and rate-limit
        // responses. Other application codes retain the internal-error fallback.
        400..=599 => StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

#[cfg(test)]
mod tests {
    use super::{ApiError, ServiceError, ServiceResult};
    use axum::{body::to_bytes, http::StatusCode, response::IntoResponse};
    use serde_json::{Value, json};

    async fn check_error_response(response: axum::response::Response, code: u16, status: u16) {
        assert_eq!(response.status().as_u16(), status);
        let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            body,
            json!({"code":code,"data":null,"count":0,"msg":"closed_error"})
        );
    }

    #[tokio::test]
    async fn result_envelope_preserves_http_error_status_and_body() {
        for code in [
            400, 401, 403, 404, 405, 409, 410, 422, 429, 451, 499, 500, 502, 503, 504, 599,
        ] {
            let response =
                ServiceResult::<()>::failure(ServiceError::with_message(code, "closed_error"))
                    .into_response();
            check_error_response(response, code, code).await;
        }
    }

    #[tokio::test]
    async fn api_error_preserves_http_error_status_and_body() {
        for code in [404, 409, 422, 429, 500, 503] {
            let response =
                ApiError::from(ServiceError::with_message(code, "closed_error")).into_response();
            check_error_response(response, code, code).await;
        }
    }

    #[tokio::test]
    async fn non_error_application_codes_keep_internal_error_fallback() {
        for code in [
            0,
            99,
            100,
            199,
            201,
            204,
            206,
            299,
            301,
            399,
            600,
            999,
            1001,
            u16::MAX,
        ] {
            let result =
                ServiceResult::<()>::failure(ServiceError::with_message(code, "closed_error"));
            check_error_response(result.into_response(), code, 500).await;
            let error = ApiError::from(ServiceError::with_message(code, "closed_error"));
            check_error_response(error.into_response(), code, 500).await;
        }
    }

    #[tokio::test]
    async fn success_envelope_keeps_existing_status_and_body() {
        let response = ServiceResult::success(json!({"value":1})).into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(
            body,
            json!({"code":200,"data":{"value":1},"count":0,"msg":"SUCCESS"})
        );
    }
}

#[cfg(test)]
mod local_error_constructor_tests {
    use axum::{body::to_bytes, http::StatusCode, response::IntoResponse};
    use serde_json::Value;

    use super::ApiError;

    async fn response_json(error: ApiError) -> (StatusCode, Value) {
        let response = error.into_response();
        let status = response.status();
        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("response body should be readable");
        let json = serde_json::from_slice(&body).expect("response body should be valid JSON");
        (status, json)
    }

    #[tokio::test]
    async fn conflict_maps_to_http_409() {
        let (status, body) = response_json(ApiError::conflict("revision conflict")).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["code"], 409);
        assert_eq!(body["msg"], "revision conflict");
    }

    #[tokio::test]
    async fn unprocessable_entity_maps_to_http_422() {
        let (status, body) =
            response_json(ApiError::unprocessable_entity("validation failed")).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body["code"], 422);
        assert_eq!(body["msg"], "validation failed");
    }
}
