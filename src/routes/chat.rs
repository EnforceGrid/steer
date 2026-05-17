use axum::{Extension, extract::Request};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use std::sync::Arc;

use crate::middleware::TenantContext;
use crate::pipeline::PipelineState;

pub async fn chat_completions(
    Extension(state): Extension<Arc<PipelineState>>,
    req: Request,
) -> Response {
    let (parts, body) = req.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 10 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    // Extract the tenant_id resolved by ApiKeyLayer middleware (honours X-Steer-Tenant-Id
    // for service-key callers).  Passing it as override_tenant ensures audit entries are
    // stamped with the correct tenant rather than the fallback "default".
    let tenant_ctx = parts.extensions.get::<TenantContext>().cloned();
    let override_tenant = tenant_ctx.map(|c| c.tenant_id);

    crate::pipeline::run(
        &state,
        parts.method,
        parts.uri,
        parts.headers,
        body_bytes,
        override_tenant,
    ).await
}

pub async fn messages(
    Extension(state): Extension<Arc<PipelineState>>,
    req: Request,
) -> Response {
    chat_completions(Extension(state), req).await
}

pub async fn passthrough(
    Extension(state): Extension<Arc<PipelineState>>,
    req: Request,
) -> Response {
    let (parts, _body) = req.into_parts();
    let upstream_url = crate::routing::build_upstream_url(
        &state.config.upstream.base_url,
        parts.uri.path(),
        parts.uri.query(),
    );

    let fwd = crate::headers::forward_headers(&parts.headers);
    let hmap = crate::pipeline::map_to_header_map(&fwd);

    match state.http_client.get(&upstream_url).headers(hmap).send().await {
        Ok(resp) => {
            let status = resp.status();
            let axum_status = StatusCode::from_u16(status.as_u16())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            let body = resp.bytes().await.unwrap_or_default();
            (axum_status, body).into_response()
        }
        Err(_e) => StatusCode::BAD_GATEWAY.into_response(),
    }
}
