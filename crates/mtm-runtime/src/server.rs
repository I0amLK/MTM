use std::net::TcpListener;
use std::sync::Arc;

use mtm_contracts::{ErrorCategory, ReCtmError};

use crate::RuntimeApplication;

pub fn serve_bound(
    listener: TcpListener,
    application: Arc<RuntimeApplication>,
) -> Result<(), ReCtmError> {
    listener.set_nonblocking(true).map_err(io_error)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(io_error)?;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::from_std(listener).map_err(io_error)?;
        let router = mtm_gateway::build_router(Arc::clone(&application.gateway));
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(io_error)?;
        application.close()?;
        Ok(())
    })
}

async fn shutdown_signal() {
    #[cfg(unix)]
    if let Ok(mut terminate) =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
        return;
    }
    let _ = tokio::signal::ctrl_c().await;
}

fn io_error(error: std::io::Error) -> ReCtmError {
    ReCtmError::new("RUNTIME_SERVER_IO_ERROR", error.to_string())
        .with_category(ErrorCategory::Runtime)
}
