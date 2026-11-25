use crate::{
    config::{AdmissionConfig, valid_bearer_token},
    errors::ServiceError,
    metrics::{self, AcceptedAuthorizationBatch, AdmissionRejectionReason},
};
use actix_service::{Service, Transform};
use actix_web::{
    Error, HttpMessage, ResponseError,
    body::EitherBody,
    dev::ServiceRequest,
    dev::ServiceResponse,
    http::header::{AUTHORIZATION, HeaderMap, HeaderName, HeaderValue, WWW_AUTHENTICATE},
};
use futures_util::future::{self, LocalBoxFuture, Ready};
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};
use std::task::{Context, Poll};
use std::time::Instant;
use tracing::{Instrument, Level, info, span, warn};
use uuid::Uuid;

#[derive(Clone)]
pub struct RequestIds {
    pub request_id: String,
    pub correlation_id: String,
}

#[derive(Clone, Copy)]
pub struct ResolvedClientIp(pub IpAddr);

#[derive(Clone)]
pub struct AccessControlMiddleware {
    config: AdmissionConfig,
}

impl AccessControlMiddleware {
    pub fn new(config: AdmissionConfig) -> Self {
        Self { config }
    }
}

impl<S, B> Transform<S, ServiceRequest> for AccessControlMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = AccessControlMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        future::ready(Ok(AccessControlMiddlewareService {
            service,
            config: self.config.clone(),
        }))
    }
}

pub struct AccessControlMiddlewareService<S> {
    service: S,
    config: AdmissionConfig,
}

impl<S, B> Service<ServiceRequest> for AccessControlMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        if !is_protected_request(&req) {
            return call_service(&self.service, req);
        }

        if self.config.has_acl() {
            let client_ip = match resolve_client_ip(&req, &self.config.trusted_proxies) {
                Ok(Some(ip)) => ip,
                Ok(None) | Err(ClientIpError::MalformedForwardedFor) => {
                    return reject(
                        req,
                        ServiceError::ClientNotAllowed,
                        AdmissionRejectionReason::ClientIpUnresolved,
                        None,
                    );
                }
            };
            if !self.config.client_allowlist.allows(client_ip) {
                return reject(
                    req,
                    ServiceError::ClientNotAllowed,
                    AdmissionRejectionReason::ClientIpNotAllowed,
                    Some(client_ip),
                );
            }
            req.extensions_mut().insert(ResolvedClientIp(client_ip));
        }

        if !self.config.access_tokens.is_empty() {
            match bearer_token(req.headers()) {
                Ok(token) if self.config.access_tokens.matches(token) => {}
                Ok(_) => {
                    return reject(
                        req,
                        ServiceError::InvalidAccessToken,
                        AdmissionRejectionReason::AccessTokenInvalid,
                        None,
                    );
                }
                Err(BearerError::Missing) => {
                    return reject(
                        req,
                        ServiceError::InvalidAccessToken,
                        AdmissionRejectionReason::AccessTokenMissing,
                        None,
                    );
                }
                Err(BearerError::Malformed) => {
                    return reject(
                        req,
                        ServiceError::InvalidAccessToken,
                        AdmissionRejectionReason::AccessTokenMalformed,
                        None,
                    );
                }
            }
        }

        call_service(&self.service, req)
    }
}

fn call_service<S, B>(
    service: &S,
    req: ServiceRequest,
) -> LocalBoxFuture<'static, Result<ServiceResponse<EitherBody<B>>, Error>>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    let fut = service.call(req);
    Box::pin(async move { fut.await.map(ServiceResponse::map_into_left_body) })
}

fn reject<B: 'static>(
    req: ServiceRequest,
    error: ServiceError,
    reason: AdmissionRejectionReason,
    client_ip: Option<IpAddr>,
) -> LocalBoxFuture<'static, Result<ServiceResponse<EitherBody<B>>, Error>> {
    metrics::record_admission_rejection(reason);
    warn!(
        message = "Rejected request by admission control",
        reason = reason.as_str(),
        client_ip = client_ip.map(|ip| ip.to_string()).as_deref(),
    );

    let mut response = error.error_response();
    if matches!(error, ServiceError::InvalidAccessToken) {
        response
            .headers_mut()
            .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    }
    let response = req.into_response(response).map_into_right_body();
    Box::pin(async move { Ok(response) })
}

fn is_protected_request(req: &ServiceRequest) -> bool {
    is_protected_path(req.match_info().as_str())
}

pub fn is_protected_path(path: &str) -> bool {
    path == "/metrics" || path == "/api/v1" || path.starts_with("/api/v1/")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BearerError {
    Missing,
    Malformed,
}

fn bearer_token(headers: &HeaderMap) -> Result<&str, BearerError> {
    let mut values = headers.get_all(AUTHORIZATION);
    let Some(value) = values.next() else {
        return Err(BearerError::Missing);
    };
    if values.next().is_some() {
        return Err(BearerError::Malformed);
    }
    let raw = value.to_str().map_err(|_| BearerError::Malformed)?;
    let (scheme, token) = raw.split_once(' ').ok_or(BearerError::Malformed)?;
    if !scheme.eq_ignore_ascii_case("Bearer") || !valid_bearer_token(token) {
        return Err(BearerError::Malformed);
    }
    Ok(token)
}

const CORRELATION_ID: HeaderName = HeaderName::from_static("x-correlation-id");
const REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientIpError {
    MalformedForwardedFor,
}

fn resolve_client_ip(
    req: &ServiceRequest,
    trusted_proxies: &[IpNet],
) -> Result<Option<IpAddr>, ClientIpError> {
    let Some(peer) = req.peer_addr().map(|address| address.ip()) else {
        return Ok(None);
    };

    if !ip_in_nets(peer, trusted_proxies) {
        return Ok(Some(peer));
    }

    forwarded_client_ip(req.headers(), trusted_proxies)
}

fn forwarded_client_ip(
    headers: &HeaderMap,
    trusted_proxies: &[IpNet],
) -> Result<Option<IpAddr>, ClientIpError> {
    let mut first = None;
    let mut rightmost_untrusted = None;
    for value in headers.get_all("x-forwarded-for") {
        let value = value
            .to_str()
            .map_err(|_| ClientIpError::MalformedForwardedFor)?;
        for token in value.split(',') {
            let ip = parse_ip_token(token).ok_or(ClientIpError::MalformedForwardedFor)?;
            first.get_or_insert(ip);
            if !ip_in_nets(ip, trusted_proxies) {
                rightmost_untrusted = Some(ip);
            }
        }
    }
    Ok(rightmost_untrusted.or(first))
}

fn ip_in_nets(ip: IpAddr, nets: &[IpNet]) -> bool {
    nets.iter().any(|net| net.contains(&ip))
}

fn parse_ip_token(raw: &str) -> Option<IpAddr> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    raw.parse::<IpAddr>().ok().or_else(|| parse_socket(raw))
}

#[doc(hidden)]
pub fn resolve_client_ip_for_bench(
    req: &ServiceRequest,
    trusted_proxies: &[IpNet],
) -> Option<IpAddr> {
    resolve_client_ip(req, trusted_proxies).ok().flatten()
}

fn parse_socket(raw: &str) -> Option<IpAddr> {
    if let Ok(sa) = raw.parse::<SocketAddr>() {
        return Some(sa.ip());
    }

    raw.strip_prefix('[')
        .and_then(|raw| raw.strip_suffix(']'))
        .and_then(|ip| ip.parse::<IpAddr>().ok())
}

// Middleware factory
#[derive(Clone)]
pub struct TracingMiddleware;

impl Default for TracingMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

impl TracingMiddleware {
    pub fn new() -> Self {
        Self
    }
}

impl<S, B> Transform<S, ServiceRequest> for TracingMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = TracingMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        future::ready(Ok(TracingMiddlewareService { service }))
    }
}

pub struct TracingMiddlewareService<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for TracingMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let request_id = Uuid::new_v4().to_string();
        let correlation_id = req
            .headers()
            .get(&CORRELATION_ID)
            .and_then(|hv| hv.to_str().ok())
            .map(str::to_string)
            .unwrap_or_else(|| request_id.clone());

        // Make IDs available to downstream handlers/services
        req.extensions_mut().insert(RequestIds {
            request_id: request_id.clone(),
            correlation_id: correlation_id.clone(),
        });

        let span = span!(
            Level::INFO,
            "request",
            request_id     = %request_id,
            correlation_id = %correlation_id
        );

        let method = req.method().clone();
        let uri = req.uri().clone();
        let client_ip = req
            .extensions()
            .get::<ResolvedClientIp>()
            .map(|resolved| resolved.0)
            .or_else(|| req.peer_addr().map(|address| address.ip()));
        let client_ip_s = client_ip.map(|ip| ip.to_string());

        let start_time = Instant::now();
        info!(request_id = %request_id, correlation_id = %correlation_id, message = "Request start", method = method.as_str(), path = uri.path(), client_ip = client_ip_s.as_deref());

        let fut = self.service.call(req);

        Box::pin(
            async move {
                let mut res = fut.await?;

                let elapsed_time = start_time.elapsed();
                info!(message = "Request end", request_id = %request_id, correlation_id = %correlation_id, method = method.as_str(), path = uri.path(), client_ip = client_ip_s.as_deref(), run_time = ?elapsed_time, status_code = ?res.status());
                // Record HTTP metrics
                let status_code = res.status().as_u16();
                let metrics_path = res.request().match_pattern();
                metrics::http_metrics().observe(
                    method.as_str(),
                    metrics_path.as_deref().unwrap_or("unmatched"),
                    status_code,
                    client_ip_s.as_deref(),
                    elapsed_time.as_secs_f64(),
                );
                if let Some(batch) = res
                    .request()
                    .extensions()
                    .get::<AcceptedAuthorizationBatch>()
                    .copied()
                {
                    metrics::record_authorization_request(batch, elapsed_time.as_secs_f64());
                }

                res.headers_mut().insert(
                    REQUEST_ID,
                    HeaderValue::from_str(&request_id)
                        .unwrap_or_else(|_| HeaderValue::from_static("<failed>")),
                );

                res.headers_mut().insert(
                    CORRELATION_ID,
                    HeaderValue::from_str(&correlation_id)
                        .unwrap_or_else(|_| HeaderValue::from_static("<failed>")),
                );
                Ok(res)
            }
            .instrument(span),
        )
    }
}
