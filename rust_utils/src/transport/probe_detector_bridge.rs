use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::sync::Arc;
use vortex_redis::transport::probe_roll::RedisRoll;
use vortex_redis::transport::probe_sightings::RedisSightings;
use vortex_transport::active_probe::config::DetectorConfig;
use vortex_transport::active_probe::detector::ActiveProbeDetector;
use vortex_transport::active_probe::request::head::RequestHead;
use vortex_transport::active_probe::request::headers::HeaderSet;

#[pyclass(module = "vortex_chat", name = "ProbeDetector")]
pub struct PyProbeDetector {
    detector: ActiveProbeDetector,
    shared: bool,
}

#[pymethods]
impl PyProbeDetector {
    #[new]
    #[pyo3(signature = (signals_for_verdict=None, replay_window=None))]
    fn new(signals_for_verdict: Option<usize>, replay_window: Option<f64>) -> Self {
        let mut config = DetectorConfig::default();
        if let Some(signals) = signals_for_verdict {
            config = config.signals_for_verdict(signals);
        }
        if let Some(seconds) = replay_window {
            config = config.replay_window(seconds);
        }

        match crate::bmp::shared::backbone() {
            Some(backbone) => PyProbeDetector {
                detector: ActiveProbeDetector::with_stores(
                    config,
                    Arc::new(RedisSightings::with_limits(
                        backbone.clone(),
                        config.max_tracked_requests,
                        config.request_memory,
                    )),
                    Arc::new(RedisRoll::with_limits(
                        backbone,
                        config.max_tracked_probes,
                        config.probe_memory,
                    )),
                ),
                shared: true,
            },
            None => PyProbeDetector {
                detector: ActiveProbeDetector::new(config),
                shared: false,
            },
        }
    }

    #[getter]
    fn is_shared(&self) -> bool {
        self.shared
    }

    fn inspect(
        &self,
        py: Python<'_>,
        peer: &str,
        method: &str,
        path: &str,
        headers: Vec<(String, String)>,
        now: f64,
    ) -> (bool, String) {
        let mut set = HeaderSet::default();
        for (name, value) in &headers {
            set.put(name, value);
        }
        let request = RequestHead::new(peer, method, path, set);
        let verdict = py.allow_threads(|| self.detector.inspect(&request, now));
        (verdict.is_probe(), verdict.reason())
    }

    fn holds(&self, py: Python<'_>, peer: &str) -> bool {
        py.allow_threads(|| self.detector.holds(peer))
    }

    fn forget_stale(&self, py: Python<'_>, now: f64) {
        py.allow_threads(|| self.detector.forget_stale(now))
    }

    fn inspected(&self, py: Python<'_>) -> u64 {
        py.allow_threads(|| self.detector.stats().total_requests_inspected)
    }

    fn stats<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let counted = py.allow_threads(|| self.detector.stats());
        let out = PyDict::new(py);
        out.set_item("total_probes_detected", counted.total_probes_detected)?;
        out.set_item("known_probe_ips", counted.known_probe_ips)?;
        out.set_item("fingerprint_cache_size", counted.fingerprint_cache_size)?;
        out.set_item("shared_state", self.shared)?;
        Ok(out)
    }

    fn __repr__(&self) -> String {
        format!("<ProbeDetector shared={}>", self.shared)
    }
}
