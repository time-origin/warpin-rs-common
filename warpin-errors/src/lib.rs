use serde::Serialize;
use thiserror::Error;
use utoipa::ToSchema;

pub type ResultCode = u16;

pub const SUCCESS: ResultCode = 200;
pub const BAD_REQUEST: ResultCode = 400;
pub const UNAUTHORIZED: ResultCode = 401;
pub const FORBIDDEN: ResultCode = 403;
pub const NOT_FOUND: ResultCode = 404;
pub const INTERNAL_ERROR: ResultCode = 500;
pub const SERVICE_UNAVAILABLE: ResultCode = 503;

pub fn default_message(code: ResultCode) -> &'static str {
    match code {
        SUCCESS => "SUCCESS",
        BAD_REQUEST => "Bad request",
        UNAUTHORIZED => "Unauthorized",
        FORBIDDEN => "Forbidden",
        NOT_FOUND => "Resource not found",
        INTERNAL_ERROR => "Server internal error, please try again later",
        SERVICE_UNAVAILABLE => "Service unavailable",
        _ => "Server internal error, please try again later",
    }
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct ResultObject<T> {
    /// 业务状态码：200=成功, 400=参数错误, 401=未认证, 403=禁止, 404=未找到, 500=内部错误
    pub code: ResultCode,
    /// 业务数据
    pub data: Option<T>,
    /// 列表查询时的总记录数
    pub count: u64,
    /// 消息
    pub msg: String,
}

impl<T> ResultObject<T> {
    pub fn success(data: T) -> Self {
        Self {
            code: SUCCESS,
            data: Some(data),
            count: 0,
            msg: default_message(SUCCESS).to_string(),
        }
    }

    pub fn success_with_count(data: T, count: u64) -> Self {
        Self {
            code: SUCCESS,
            data: Some(data),
            count,
            msg: default_message(SUCCESS).to_string(),
        }
    }

    pub fn success_with_message(data: T, msg: impl Into<String>) -> Self {
        Self {
            code: SUCCESS,
            data: Some(data),
            count: 0,
            msg: msg.into(),
        }
    }

    pub fn failure(error: ServiceError) -> Self {
        Self {
            code: error.code,
            data: None,
            count: 0,
            msg: error.message,
        }
    }
}

#[derive(Debug, Error, Clone, ToSchema)]
#[error("code={code}, message={message}")]
pub struct ServiceError {
    /// 错误码
    pub code: ResultCode,
    /// 错误消息
    pub message: String,
}

impl ServiceError {
    pub fn new(code: ResultCode) -> Self {
        Self {
            code,
            message: default_message(code).to_string(),
        }
    }

    pub fn with_message(code: ResultCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::with_message(BAD_REQUEST, message)
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::with_message(UNAUTHORIZED, message)
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::with_message(FORBIDDEN, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::with_message(NOT_FOUND, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::with_message(INTERNAL_ERROR, message)
    }

    pub fn service_unavailable(message: impl Into<String>) -> Self {
        Self::with_message(SERVICE_UNAVAILABLE, message)
    }
}

pub type Result<T> = std::result::Result<T, ServiceError>;
pub type PlatformError = ServiceError;
