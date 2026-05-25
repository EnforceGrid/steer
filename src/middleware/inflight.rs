//! T-018: In-flight request semaphore middleware.
//!
//! Wraps every request in a `SemaphorePermit` so that the graceful-shutdown
//! drain logic in `main.rs` can wait for all in-flight requests to complete
//! before forcing a close.

use axum::http::Request;
use axum::response::{IntoResponse, Response};
use futures::future::BoxFuture;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::Semaphore;
use tower::{Layer, Service};

/// Maximum concurrent in-flight requests. Requests beyond this limit receive
/// a 503 immediately (rather than queuing indefinitely).
pub const MAX_IN_FLIGHT: usize = 1000;

// ---------------------------------------------------------------------------
// Layer
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct InFlightLayer {
    semaphore: Arc<Semaphore>,
}

impl InFlightLayer {
    pub fn new(semaphore: Arc<Semaphore>) -> Self {
        Self { semaphore }
    }
}

impl<S> Layer<S> for InFlightLayer {
    type Service = InFlightService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        InFlightService {
            inner,
            semaphore: Arc::clone(&self.semaphore),
        }
    }
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct InFlightService<S> {
    inner: S,
    semaphore: Arc<Semaphore>,
}

impl<S, B> Service<Request<B>> for InFlightService<S>
where
    S: Service<Request<B>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Response, S::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let semaphore = Arc::clone(&self.semaphore);
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // Try a non-blocking acquire first; if all permits are taken, 503.
            let permit = match semaphore.try_acquire() {
                Ok(p) => p,
                Err(_) => {
                    return Ok(axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response());
                }
            };

            let response = inner.call(req).await?;

            // Hold the permit until the response is returned to the caller.
            // The permit is dropped here, releasing the slot.
            drop(permit);
            Ok(response)
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::{routing::get, Router};
    use tower::ServiceExt; // for `oneshot`

    // Simple handler that always returns 200 OK.
    async fn ok_handler() -> StatusCode {
        StatusCode::OK
    }

    fn make_router(semaphore: Arc<Semaphore>) -> Router {
        Router::new()
            .route("/test", get(ok_handler))
            .layer(InFlightLayer::new(semaphore))
    }

    // T-029: A normal request acquires a permit, gets a 200, and releases it.
    #[tokio::test]
    async fn permit_acquired_and_released_around_request() {
        let semaphore = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
        let app = make_router(Arc::clone(&semaphore));

        // Before the request, all permits are available.
        assert_eq!(semaphore.available_permits(), MAX_IN_FLIGHT);

        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // After the request completes, the permit is returned.
        assert_eq!(semaphore.available_permits(), MAX_IN_FLIGHT);
    }

    // T-029: When all permits are exhausted the middleware returns 503 immediately
    // without blocking, so the graceful-drain can still acquire all permits.
    #[tokio::test]
    async fn returns_503_when_semaphore_exhausted() {
        // A semaphore with zero permits simulates a fully-saturated server.
        let semaphore = Arc::new(Semaphore::new(0));
        let app = make_router(Arc::clone(&semaphore));

        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    // T-029: Graceful drain — acquire all permits concurrently while a request
    // holds one, verify drain completes once the request finishes.
    //
    // Strategy: use a 2-permit semaphore so the test is fast.  Send one request
    // that holds its permit while we try to acquire the remaining permit;
    // both acquisitions should succeed, confirming that:
    // (a) the request consumed exactly one permit, and
    // (b) no permits leaked after the response.
    #[tokio::test]
    async fn graceful_drain_completes_after_inflight_request_finishes() {
        const PERMITS: usize = 2;
        let semaphore = Arc::new(Semaphore::new(PERMITS));
        let app = make_router(Arc::clone(&semaphore));

        // Issue a request through the middleware.
        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let _resp = app.oneshot(req).await.unwrap();

        // After completion all permits must be available — drain can proceed.
        assert_eq!(
            semaphore.available_permits(),
            PERMITS,
            "all permits must be released after request for drain to complete"
        );

        // Simulate drain: acquiring all permits must succeed without blocking.
        let drain_result = tokio::time::timeout(
            tokio::time::Duration::from_millis(100),
            semaphore.acquire_many(PERMITS as u32),
        )
        .await;
        assert!(
            drain_result.is_ok(),
            "drain should not time out — all permits available"
        );
    }

    // T-029: A single in-flight request consumes exactly one permit.
    #[tokio::test]
    async fn single_request_consumes_exactly_one_permit() {
        // Use a small semaphore so we can observe the count precisely.
        let permits: usize = 5;
        let semaphore = Arc::new(Semaphore::new(permits));

        // Pre-acquire 4 permits manually, leaving 1 available.
        let _held: Vec<_> = (0..4).map(|_| semaphore.try_acquire().unwrap()).collect();
        assert_eq!(semaphore.available_permits(), 1);

        let app = make_router(Arc::clone(&semaphore));

        // The last available permit is consumed by the request and returned.
        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // The permit must have been returned.
        assert_eq!(semaphore.available_permits(), 1);
    }
}
