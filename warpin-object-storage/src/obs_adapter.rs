//! Huawei OBS native protocol. Credentials are supplied by the calling application.
//! Object locations are complete keys relative to the bucket, without a hidden prefix.
use std::{
    collections::BTreeMap,
    fmt,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures::{StreamExt, TryStreamExt, stream::BoxStream};
use hmac::{Hmac, KeyInit, Mac};
use object_store::{
    Attribute, Attributes, CopyOptions, Extensions, GetOptions, GetResult, GetResultPayload,
    ListResult, MultipartUpload, ObjectMeta, ObjectStore, PutMode, PutMultipartOptions, PutOptions,
    PutPayload, PutResult, path::Path,
};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::{
    Method, Url,
    header::{AUTHORIZATION, DATE, HeaderMap, HeaderValue},
};
use sha1::Sha1;

const KEY_ENCODING: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~')
    .remove(b'/');

/// No environment lookup or application-specific secret paths occur in this module.
#[derive(Clone)]
pub struct ObsCredentials {
    access_key_id: String,
    secret_access_key: String,
    security_token: Option<String>,
}
impl ObsCredentials {
    pub fn new(
        access_key_id: String,
        secret_access_key: String,
        security_token: Option<String>,
    ) -> object_store::Result<Self> {
        if access_key_id.is_empty()
            || secret_access_key.is_empty()
            || security_token.as_ref().is_some_and(|v| v.is_empty())
        {
            return Err(error("OBS credentials are incomplete"));
        }
        Ok(Self {
            access_key_id,
            secret_access_key,
            security_token,
        })
    }
}
impl fmt::Debug for ObsCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ObsCredentials([REDACTED])")
    }
}

#[derive(Clone)]
pub struct ObsObjectStore {
    base: Url,
    bucket: String,
    credentials: Arc<ObsCredentials>,
    client: reqwest::Client,
}
impl fmt::Debug for ObsObjectStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ObsObjectStore([CONFIGURED])")
    }
}
impl fmt::Display for ObsObjectStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Huawei OBS")
    }
}

/// A short-lived access credential. Its Debug representation never reveals the URL.
pub struct ObsDownloadUrl {
    url: Url,
    pub expires_at: SystemTime,
}
impl ObsDownloadUrl {
    pub fn url(&self) -> &Url {
        &self.url
    }
}
impl fmt::Debug for ObsDownloadUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObsDownloadUrl")
            .field("url", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl ObsObjectStore {
    /// `endpoint` is the service endpoint; the bucket is added as a virtual host.
    pub fn new(
        endpoint: &str,
        bucket: String,
        credentials: ObsCredentials,
        timeout: Duration,
    ) -> object_store::Result<Self> {
        let mut base = Url::parse(endpoint).map_err(|_| error("OBS endpoint is invalid"))?;
        if base.scheme() != "https"
            || base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || !matches!(base.path(), "" | "/")
            || bucket.len() < 3
            || bucket.len() > 63
            || bucket
                .split('.')
                .any(|part| part.is_empty() || part.starts_with('-') || part.ends_with('-'))
            || !bucket
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.'))
            || timeout.is_zero()
        {
            return Err(error("OBS configuration is invalid"));
        }
        let host = format!(
            "{bucket}.{}",
            base.host_str()
                .ok_or_else(|| error("OBS endpoint missing"))?
        );
        base.set_host(Some(&host))
            .map_err(|_| error("OBS bucket host is invalid"))?;
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .build()
            .map_err(|_| error("OBS transport configuration failed"))?;
        Ok(Self {
            base,
            bucket,
            credentials: Arc::new(credentials),
            client,
        })
    }

    fn target(&self, key: &Path, version: Option<&str>) -> object_store::Result<(Url, String)> {
        let mut url = self.base.clone();
        url.set_path(&format!(
            "/{}",
            utf8_percent_encode(key.as_ref(), KEY_ENCODING)
        ));
        let mut resource = format!("/{}{}", self.bucket, url.path());
        if let Some(version) = version {
            if version.is_empty() {
                return Err(error("OBS object version is empty"));
            }
            url.query_pairs_mut().append_pair("versionId", version);
            resource.push_str("?versionId=");
            resource.push_str(version);
        }
        Ok((url, resource))
    }

    fn authorization(
        &self,
        method: &Method,
        resource: &str,
        headers: &HeaderMap,
        date: &str,
    ) -> object_store::Result<HeaderValue> {
        let custom: BTreeMap<_, _> = headers
            .iter()
            .filter(|(k, _)| k.as_str().starts_with("x-obs-"))
            .map(|(k, v)| {
                Ok((
                    k.as_str(),
                    v.to_str()
                        .map_err(|_| error("OBS signed header is invalid"))?
                        .trim(),
                ))
            })
            .collect::<object_store::Result<_>>()?;
        let canonical_headers = custom
            .iter()
            .map(|(k, v)| format!("{k}:{v}\n"))
            .collect::<String>();
        let content_type = headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let canonical = format!(
            "{}\n\n{}\n{}\n{}{}",
            method.as_str(),
            content_type,
            date,
            canonical_headers,
            resource
        );
        let signature = self.signature(&canonical)?;
        let mut value = HeaderValue::from_str(&format!(
            "OBS {}:{signature}",
            self.credentials.access_key_id
        ))
        .map_err(|_| error("OBS credentials are invalid"))?;
        value.set_sensitive(true);
        Ok(value)
    }

    fn signature(&self, canonical: &str) -> object_store::Result<String> {
        let mut mac = Hmac::<Sha1>::new_from_slice(self.credentials.secret_access_key.as_bytes())
            .map_err(|_| error("OBS signing failed"))?;
        mac.update(canonical.as_bytes());
        Ok(STANDARD.encode(mac.finalize().into_bytes()))
    }

    async fn request(
        &self,
        method: Method,
        key: &Path,
        version: Option<&str>,
        mut headers: HeaderMap,
        body: Option<Bytes>,
    ) -> object_store::Result<reqwest::Response> {
        let (url, resource) = self.target(key, version)?;
        let date = httpdate::fmt_http_date(SystemTime::now());
        headers.insert(DATE, header(&date)?);
        if let Some(token) = &self.credentials.security_token {
            let mut value = header(token)?;
            value.set_sensitive(true);
            headers.insert("x-obs-security-token", value);
        }
        headers.insert(
            AUTHORIZATION,
            self.authorization(&method, &resource, &headers, &date)?,
        );
        let mut request = self.client.request(method, url).headers(headers);
        if let Some(body) = body {
            request = request.body(body);
        }
        let response = request
            .send()
            .await
            .map_err(|_| error("OBS request failed; write outcome may be unknown"))?;
        match response.status().as_u16() {
            200..=299 => Ok(response),
            404 => Err(object_store::Error::NotFound {
                path: key.to_string(),
                source: "OBS object missing".into(),
            }),
            401 => Err(object_store::Error::Unauthenticated {
                path: key.to_string(),
                source: "OBS authentication failed".into(),
            }),
            403 => Err(object_store::Error::PermissionDenied {
                path: key.to_string(),
                source: "OBS request denied".into(),
            }),
            304 => Err(object_store::Error::NotModified {
                path: key.to_string(),
                source: "OBS object not modified".into(),
            }),
            412 => Err(object_store::Error::Precondition {
                path: key.to_string(),
                source: "OBS condition failed".into(),
            }),
            _ => Err(error("OBS returned a non-success response")),
        }
    }

    /// Exact version deletion; no bucket or prefix listing is involved.
    pub async fn delete_version(
        &self,
        key: &Path,
        version: Option<&str>,
    ) -> object_store::Result<()> {
        self.request(Method::DELETE, key, version, HeaderMap::new(), None)
            .await?;
        Ok(())
    }

    pub fn presign_get(
        &self,
        key: &Path,
        version: Option<&str>,
        expires_at: SystemTime,
    ) -> object_store::Result<ObsDownloadUrl> {
        if expires_at <= SystemTime::now() {
            return Err(error("OBS URL expiry must be in the future"));
        }
        let expires = expires_at
            .duration_since(UNIX_EPOCH)
            .map_err(|_| error("OBS URL expiry is invalid"))?
            .as_secs();
        let (mut url, mut resource) = self.target(key, version)?;
        if let Some(token) = &self.credentials.security_token {
            resource.push(if version.is_some() { '&' } else { '?' });
            resource.push_str("x-obs-security-token=");
            resource.push_str(token);
            url.query_pairs_mut()
                .append_pair("x-obs-security-token", token);
        }
        let signature = self.signature(&format!("GET\n\n\n{expires}\n{resource}"))?;
        url.query_pairs_mut()
            .append_pair("AccessKeyId", &self.credentials.access_key_id)
            .append_pair("Expires", &expires.to_string())
            .append_pair("Signature", &signature);
        Ok(ObsDownloadUrl { url, expires_at })
    }
}

#[async_trait]
impl ObjectStore for ObsObjectStore {
    async fn put_opts(
        &self,
        key: &Path,
        payload: PutPayload,
        options: PutOptions,
    ) -> object_store::Result<PutResult> {
        // OBS native PUT does not document atomic create/update conditions.
        // Returning unsupported preserves ObjectStore's contract rather than emulating it with HEAD+PUT.
        if !matches!(options.mode, PutMode::Overwrite) {
            return Err(unsupported("conditional PUT"));
        }
        if !options.tags.is_empty() {
            return Err(unsupported("PUT tags"));
        }
        let mut headers = HeaderMap::new();
        for (attribute, value) in options.attributes.iter() {
            let name = match attribute {
                Attribute::ContentType => "content-type".to_owned(),
                Attribute::ContentEncoding => "content-encoding".to_owned(),
                Attribute::ContentLanguage => "content-language".to_owned(),
                Attribute::ContentDisposition => "content-disposition".to_owned(),
                Attribute::CacheControl => "cache-control".to_owned(),
                Attribute::Metadata(name) => format!("x-obs-meta-{name}"),
                _ => return Err(unsupported("PUT attribute")),
            };
            headers.insert(
                reqwest::header::HeaderName::from_bytes(name.as_bytes())
                    .map_err(|_| error("OBS metadata name is invalid"))?,
                header(value.as_ref())?,
            );
        }
        let response = self
            .request(Method::PUT, key, None, headers, Some(payload.into()))
            .await?;
        Ok(PutResult {
            e_tag: response_header(response.headers(), "etag"),
            version: response_header(response.headers(), "x-obs-version-id"),
            extensions: Extensions::new(),
        })
    }

    async fn get_opts(&self, key: &Path, options: GetOptions) -> object_store::Result<GetResult> {
        let mut headers = HeaderMap::new();
        if let Some(value) = &options.if_match {
            headers.insert("if-match", header(value)?);
        }
        if let Some(value) = &options.if_none_match {
            headers.insert("if-none-match", header(value)?);
        }
        if let Some(value) = options.if_modified_since {
            headers.insert(
                "if-modified-since",
                header(&httpdate::fmt_http_date(value.into()))?,
            );
        }
        if let Some(value) = options.if_unmodified_since {
            headers.insert(
                "if-unmodified-since",
                header(&httpdate::fmt_http_date(value.into()))?,
            );
        }
        if let Some(range) = &options.range {
            range
                .is_valid()
                .map_err(|_| error("OBS range is invalid"))?;
            headers.insert("range", header(&range.to_string())?);
        }
        let response = self
            .request(
                if options.head {
                    Method::HEAD
                } else {
                    Method::GET
                },
                key,
                options.version.as_deref(),
                headers,
                None,
            )
            .await?;
        let h = response.headers();
        let length = response_header(h, "content-length")
            .and_then(|v| v.parse::<u64>().ok())
            .ok_or_else(|| error("OBS content length is missing"))?;
        let range = if response.status().as_u16() == 206 {
            let text = response_header(h, "content-range")
                .ok_or_else(|| error("OBS content range is missing"))?;
            let (bounds, total) = text
                .strip_prefix("bytes ")
                .and_then(|v| v.split_once('/'))
                .ok_or_else(|| error("OBS content range is invalid"))?;
            let (start, end) = bounds
                .split_once('-')
                .ok_or_else(|| error("OBS range bounds invalid"))?;
            let start = start
                .parse::<u64>()
                .map_err(|_| error("OBS range start invalid"))?;
            let end = end
                .parse::<u64>()
                .map_err(|_| error("OBS range end invalid"))?
                .checked_add(1)
                .ok_or_else(|| error("OBS range overflow"))?;
            let total = total
                .parse::<u64>()
                .map_err(|_| error("OBS range total invalid"))?;
            if start >= end || end > total {
                return Err(error("OBS content range bounds invalid"));
            }
            (start..end, total)
        } else {
            (0..length, length)
        };
        let expected = options
            .range
            .as_ref()
            .map(|r| {
                r.as_range(range.1)
                    .map_err(|_| error("OBS range outside object"))
            })
            .transpose()?
            .unwrap_or(0..range.1);
        if !options.head && (range.0 != expected || range.0.end - range.0.start != length) {
            return Err(error("OBS returned an unexpected byte range"));
        }
        let meta = ObjectMeta {
            location: key.clone(),
            size: range.1,
            e_tag: response_header(h, "etag"),
            version: response_header(h, "x-obs-version-id"),
            last_modified: response_header(h, "last-modified")
                .and_then(|v| httpdate::parse_http_date(&v).ok())
                .map(DateTime::<Utc>::from)
                .ok_or_else(|| error("OBS last-modified missing"))?,
        };
        options.check_preconditions(&meta)?;
        let mut attributes = Attributes::new();
        for (name, value) in h {
            let attribute = if name.as_str() == "content-type" {
                Some(Attribute::ContentType)
            } else {
                name.as_str()
                    .strip_prefix("x-obs-meta-")
                    .map(|n| Attribute::Metadata(n.to_owned().into()))
            };
            if let Some(attribute) = attribute {
                attributes.insert(
                    attribute,
                    value
                        .to_str()
                        .map_err(|_| error("OBS metadata value invalid"))?
                        .to_owned()
                        .into(),
                );
            }
        }
        let stream = response
            .bytes_stream()
            .map_err(|_| error("OBS response stream failed"))
            .boxed();
        Ok(GetResult {
            payload: GetResultPayload::Stream(stream),
            meta,
            range: range.0,
            attributes,
            extensions: Extensions::new(),
        })
    }

    async fn put_multipart_opts(
        &self,
        _: &Path,
        _: PutMultipartOptions,
    ) -> object_store::Result<Box<dyn MultipartUpload>> {
        Err(unsupported("multipart upload"))
    }
    fn delete_stream(
        &self,
        locations: BoxStream<'static, object_store::Result<Path>>,
    ) -> BoxStream<'static, object_store::Result<Path>> {
        let store = self.clone();
        locations
            .and_then(move |key| {
                let store = store.clone();
                async move {
                    store.delete_version(&key, None).await?;
                    Ok(key)
                }
            })
            .boxed()
    }
    fn list(&self, _: Option<&Path>) -> BoxStream<'static, object_store::Result<ObjectMeta>> {
        futures::stream::once(async {
            Err(unsupported("list; use application-owned object references"))
        })
        .boxed()
    }
    async fn list_with_delimiter(&self, _: Option<&Path>) -> object_store::Result<ListResult> {
        Err(unsupported("list with delimiter"))
    }
    async fn copy_opts(&self, _: &Path, _: &Path, _: CopyOptions) -> object_store::Result<()> {
        Err(unsupported("copy"))
    }
}

fn header(value: &str) -> object_store::Result<HeaderValue> {
    HeaderValue::from_str(value).map_err(|_| error("OBS header value is invalid"))
}
fn response_header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}
fn error(message: &'static str) -> object_store::Error {
    object_store::Error::Generic {
        store: "Huawei OBS",
        source: message.into(),
    }
}
fn unsupported(operation: &'static str) -> object_store::Error {
    object_store::Error::NotSupported {
        source: format!("OBS {operation} is not supported by this adapter").into(),
    }
}

#[cfg(test)]
mod tests;
