use std::sync::Arc;

use axum::{
    Json,
    body::Body,
    extract::{FromRequest, Query, Request, State, WebSocketUpgrade, ws::Message},
    response::IntoResponse,
};
use http::HeaderMap;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::app::api::AppState;

#[cfg(feature = "jemallocator")]
use tikv_jemalloc_ctl::epoch;

use super::utils::is_request_websocket;

#[derive(Deserialize)]
pub struct GetMemoryQuery {
    interval: Option<u64>,
}

#[derive(Serialize)]
struct GetMemoryResponse {
    inuse: usize,
    oslimit: usize,
}
pub async fn handle(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    q: Query<GetMemoryQuery>,
    req: Request<Body>,
) -> impl IntoResponse {
    if !is_request_websocket(headers) {
        let mgr = state.statistics_manager.clone();
        
        let oslimit = state.memory_limit.load(std::sync::atomic::Ordering::Relaxed) as usize;

        let snapshot = GetMemoryResponse {
            inuse: mgr.memory_usage(),
            oslimit,
        };
        return Json(snapshot).into_response();
    }

    let ws = match WebSocketUpgrade::from_request(req, &state).await {
        Ok(ws) => ws,
        Err(e) => {
            warn!("ws upgrade error: {}", e);
            return e.into_response();
        }
    };

    ws.on_failed_upgrade(|e| {
        warn!("ws upgrade error: {}", e);
    })
    .on_upgrade(move |mut socket| async move {
        let interval = q.interval;

        let mgr = state.statistics_manager.clone();

        loop {
            let oslimit = state.memory_limit.load(std::sync::atomic::Ordering::Relaxed) as usize;

            let snapshot = GetMemoryResponse {
                inuse: mgr.memory_usage(),
                oslimit,
            };
            let j = serde_json::to_vec(&snapshot).unwrap();
            let body = String::from_utf8(j).unwrap();

            if let Err(e) = socket.send(Message::Text(body.into())).await {
                debug!("send memory snapshot failed: {}", e);
                break;
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(
                interval.unwrap_or(1),
            ))
            .await;
        }
    })
}

#[cfg(feature = "mimalloc")]
unsafe extern "C" {
    fn mi_collect(force: bool);
}

pub async fn flush() -> impl IntoResponse {
    debug!("manual memory gc triggered");
    perform_gc(true);
    http::StatusCode::NO_CONTENT
}

#[cfg(any(feature = "mimalloc", feature = "jemallocator"))]
pub fn perform_gc(force: bool) {
    debug!("performing GC (force={})", force);
    #[cfg(feature = "mimalloc")]
    unsafe {
        mi_collect(force);
    }
    #[cfg(feature = "jemallocator")]
    {
        if let Ok(e) = epoch::mib() {
            let _ = e.advance();
        }
    }
}

#[cfg(not(any(feature = "mimalloc", feature = "jemallocator")))]
pub fn perform_gc(_force: bool) {
    // No-op for system allocator
}

#[derive(Deserialize)]
pub struct SetMemoryLimitRequest {
    // Memory limit in bytes
    limit: u64,
}

pub async fn set_limit(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SetMemoryLimitRequest>,
) -> impl IntoResponse {
    let limit = payload.limit;
    debug!("setting soft memory limit to {} bytes", limit);

    crate::ALLOCATOR_LIMIT.store(limit, std::sync::atomic::Ordering::Relaxed);
    state.memory_limit.store(limit, std::sync::atomic::Ordering::Relaxed);

    http::StatusCode::NO_CONTENT
}
