# warpin-dingtalk

Typed DingTalk OpenAPI client primitives for Warpin services.

## Configuration

Construct a DingTalkConfig with an application key and secret, validate it, and
then create a DingTalkClient. Optional corporate, application, agent, and
callback identifiers remain service configuration; callers must load their
values from an approved secret or configuration provider.

The default client accepts only the official API origins:

- https://api.dingtalk.com
- https://oapi.dingtalk.com

Custom origins are rejected unless the caller supplies an explicit
`DingTalkEndpointPolicy::TrustedOrigins` value. API and legacy OAPI origins are
purpose-bound separately. Every configured base and trusted origin must use
HTTPS and must not contain user information, a query, or a fragment.

`DingTalkTransportPolicy` applies bounded connect, request, and read timeouts.
The production client never follows redirects, accepts HTTPS only, and ignores
ambient proxy configuration. Arbitrary `reqwest::Client` injection is not
supported because it could bypass these outbound security controls.

## Security contract

- DingTalkConfig, DingTalkClient, cached tokens, and OAuth request or response
  types implement secret-safe Debug output.
- Transport and decode failures never include the request URL. This matters
  because legacy DingTalk OAPI operations require an access token in the query
  string.
- Non-success HTTP response bodies and provider messages are never copied into
  ServiceError.
- Boundary errors expose only a stable kind, optional numeric HTTP or provider
  code, and retryability.
- Provider and user-content DTOs intentionally do not implement `Debug`.
  Signed attachment URL results provide only a redacted `Debug`
  implementation.
- Application secrets, callback tokens, access tokens, signed URLs, and raw
  provider bodies must not be logged.

Stable boundary kinds currently include:

- dingtalk_invalid_url
- dingtalk_endpoint_policy_violation
- dingtalk_transport_policy_violation
- dingtalk_client_build_failed
- dingtalk_transport_failed
- dingtalk_response_decode_failed
- dingtalk_http_status_error
- dingtalk_api_error
- dingtalk_oapi_error

## Example

    use warpin_dingtalk::{DingTalkClient, DingTalkConfig};

    let config = DingTalkConfig {
        corp_id: None,
        app_id: None,
        agent_id: None,
        app_key: std::env::var("DINGTALK_APP_KEY")?,
        app_secret: std::env::var("DINGTALK_APP_SECRET")?,
        callback_token: None,
        api_base: "https://api.dingtalk.com".to_owned(),
        oapi_base: "https://oapi.dingtalk.com".to_owned(),
    };
    let client = DingTalkClient::new(config)?;

Do not format the environment values, configuration, client, request URL, or
provider response into application logs.

## License

MIT
