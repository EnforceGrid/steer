use crate::handover::{HoldStatus, HoldStore};
use crate::middleware::TenantContext;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{
    extract::{Path, Query},
    Extension, Json,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

pub async fn get_hold(
    Path(hold_id): Path<String>,
    Extension(store): Extension<Arc<HoldStore>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    match store.get(&hold_id) {
        Some(hold) => Ok(Json(serde_json::to_value(hold).unwrap())),
        None => Err(StatusCode::NOT_FOUND),
    }
}

#[derive(Deserialize)]
pub struct HoldAction {
    pub action: String,
}

pub async fn resolve_hold(
    Path(hold_id): Path<String>,
    Extension(store): Extension<Arc<HoldStore>>,
    Json(body): Json<HoldAction>,
) -> StatusCode {
    let status = match body.action.as_str() {
        "approve" => HoldStatus::Approved,
        "reject" => HoldStatus::Rejected,
        _ => return StatusCode::BAD_REQUEST,
    };
    if store.update_status(&hold_id, status) {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

#[derive(Deserialize)]
pub struct HoldListQuery {
    pub status: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// GET /api/v1/holds — list all holds for the calling tenant.
pub async fn list_holds(
    Query(params): Query<HoldListQuery>,
    Extension(store): Extension<Arc<HoldStore>>,
    ctx: Option<Extension<TenantContext>>,
) -> impl IntoResponse {
    let status_filter = params.status.as_deref().and_then(|s| match s {
        "pending" => Some(HoldStatus::Pending),
        "approved" => Some(HoldStatus::Approved),
        "rejected" => Some(HoldStatus::Rejected),
        "expired" => Some(HoldStatus::Expired),
        _ => None,
    });

    let tenant_id = ctx
        .as_ref()
        .map(|Extension(c)| c.tenant_id.as_str())
        .unwrap_or("default");
    let all = store.list_for_tenant(tenant_id, status_filter.as_ref());

    let limit = params.limit.unwrap_or(50).min(200);
    let offset = params.offset.unwrap_or(0);
    let total = all.len();
    let has_more = offset + limit < total;

    let page: Vec<_> = all.into_iter().skip(offset).take(limit).collect();

    Json(json!({
        "holds": page,
        "total": total,
        "has_more": has_more,
    }))
}
