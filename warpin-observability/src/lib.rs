use tracing_subscriber::{EnvFilter, fmt};

pub fn init_tracing(service_name: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("{service_name}=info,info")));

    let _ = fmt().with_env_filter(filter).try_init();
}
