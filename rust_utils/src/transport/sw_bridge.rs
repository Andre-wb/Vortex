use pyo3::prelude::*;
use pyo3::types::PyDict;
use vortex_transport::sw::config::SwConfig;
use vortex_transport::sw::profile;

#[pyclass(module = "vortex_chat", name = "ServiceWorkerProfile")]
pub struct PyServiceWorkerProfile {
    config: SwConfig,
}

#[pymethods]
impl PyServiceWorkerProfile {
    #[new]
    fn new() -> Self {
        PyServiceWorkerProfile {
            config: SwConfig::default(),
        }
    }

    #[pyo3(signature = (transports, cdn_url="", meek_url=""))]
    fn build<'py>(
        &self,
        py: Python<'py>,
        transports: Vec<String>,
        cdn_url: &str,
        meek_url: &str,
    ) -> PyResult<Bound<'py, PyDict>> {
        let built = profile::of(&self.config, &transports, cdn_url, meek_url);

        let padding = PyDict::new(py);
        padding.set_item("enabled", built.padding_enabled)?;
        padding.set_item("buckets", built.padding_buckets)?;
        padding.set_item("promote_probability", built.padding_promote_probability)?;
        padding.set_item("tile_step", built.padding_tile_step)?;

        let retry = PyDict::new(py);
        retry.set_item("max_attempts", built.retry_max_attempts)?;
        retry.set_item("backoff_base", built.retry_backoff_base_ms)?;
        retry.set_item("backoff_max", built.retry_backoff_max_ms)?;

        let out = PyDict::new(py);
        out.set_item("version", built.version)?;
        out.set_item("transports", built.transports)?;
        out.set_item("primary_transport", built.primary_transport)?;
        out.set_item("cdn_relay_url", built.cdn_relay_url)?;
        out.set_item("meek_url", built.meek_url)?;
        out.set_item("cache_ttl", built.cache_ttl_secs)?;
        out.set_item("probe_interval", built.probe_interval_secs)?;
        out.set_item("probe_interval_min", built.probe_interval_min_secs)?;
        out.set_item("probe_interval_max", built.probe_interval_max_secs)?;
        out.set_item("padding", padding)?;
        out.set_item("retry", retry)?;
        Ok(out)
    }

    fn target_for(&self, length: u32) -> u32 {
        self.config.padding.target_for(length)
    }

    #[getter]
    fn buckets(&self) -> Vec<u32> {
        self.config.padding.buckets()
    }

    #[getter]
    fn tile_step(&self) -> u32 {
        self.config.padding.tile_step
    }
}
