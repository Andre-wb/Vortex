use crate::interop::facade;
use crate::observability::metric_names;
use crate::python::body_plan::PyBodyPlan;
use crate::python::engine::PyWafEngine;
use crate::python::guard::PyWafGuard;
use crate::python::response::PyWafResponse;
use crate::redis::shared;
use crate::rules::catalog::total_patterns;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use vortex_redis::config::RedisConfig;
use vortex_redis::error::BackboneError;

#[pyfunction]
#[pyo3(signature = (peer, headers, trusted_proxies))]
fn resolve_client_ip(
    peer: Option<String>,
    headers: Vec<(String, String)>,
    trusted_proxies: Vec<String>,
) -> String {
    facade::resolve_client_ip(peer.as_deref(), &headers, &trusted_proxies)
}

#[pyfunction]
#[pyo3(signature = (url, pool_size=None, key_prefix=None))]
fn connect_redis(
    py: Python<'_>,
    url: &str,
    pool_size: Option<usize>,
    key_prefix: Option<String>,
) -> PyResult<bool> {
    let mut config = RedisConfig::new(url);
    if let Some(size) = pool_size {
        config = config.pool_size(size);
    }
    if let Some(prefix) = key_prefix {
        config = config.key_prefix(prefix);
    }

    match py.allow_threads(|| shared::connect(config)) {
        Ok(()) => Ok(true),
        Err(BackboneError::Unconfigured) => Ok(false),
        Err(error) => Err(PyRuntimeError::new_err(error.to_string())),
    }
}

#[pyfunction]
fn is_shared() -> bool {
    shared::is_shared()
}

fn metric_names_dict<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
    let counters = PyDict::new(py);
    for (name, key) in metric_names::COUNTERS {
        counters.set_item(*name, *key)?;
    }
    let gauges = PyDict::new(py);
    for (name, key) in metric_names::GAUGES {
        gauges.set_item(*name, *key)?;
    }

    let out = PyDict::new(py);
    out.set_item("counters", counters)?;
    out.set_item("gauges", gauges)?;
    out.set_item("rule_triggers", metric_names::RULE_TRIGGERS_TOTAL)?;
    out.set_item("rule_label", metric_names::RULE_LABEL)?;
    Ok(out)
}

#[pymodule]
#[pyo3(name = "vortex_waf")]
pub fn vortex_waf(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("VERSION", env!("CARGO_PKG_VERSION"))?;
    module.add("RULE_COUNT", total_patterns())?;
    module.add("METRIC_NAMES", metric_names_dict(module.py())?)?;
    module.add_class::<PyWafEngine>()?;
    module.add_class::<PyWafGuard>()?;
    module.add_class::<PyBodyPlan>()?;
    module.add_class::<PyWafResponse>()?;
    module.add_function(wrap_pyfunction!(resolve_client_ip, module)?)?;
    module.add_function(wrap_pyfunction!(connect_redis, module)?)?;
    module.add_function(wrap_pyfunction!(is_shared, module)?)?;
    Ok(())
}
