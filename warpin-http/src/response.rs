use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;
use warpin_errors::{
    BAD_REQUEST, FORBIDDEN, INTERNAL_ERROR, NOT_FOUND, ResultCode, ResultObject,
    SERVICE_UNAVAILABLE, SUCCESS, ServiceError, UNAUTHORIZED,
};

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
        BAD_REQUEST => StatusCode::BAD_REQUEST,
        UNAUTHORIZED => StatusCode::UNAUTHORIZED,
        FORBIDDEN => StatusCode::FORBIDDEN,
        NOT_FOUND => StatusCode::NOT_FOUND,
        SERVICE_UNAVAILABLE => StatusCode::SERVICE_UNAVAILABLE,
        INTERNAL_ERROR => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}
