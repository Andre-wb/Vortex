use crate::interop::facade;
use crate::observability::metric_names;
use crate::python::engine::PyWafEngine;
use crate::rules::catalog::total_patterns;
use pyo3::prelude::*;
use pyo3::types::PyDict;

#[pyfunction]
#[pyo3(signature = (peer, headers, trusted_proxies))]
fn resolve_client_ip(
    peer: Option<String>,
    headers: Vec<(String, String)>,
    trusted_proxies: Vec<String>,
) -> String {
    facade::resolve_client_ip(peer.as_deref(), &headers, &trusted_proxies)
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
    module.add_function(wrap_pyfunction!(resolve_client_ip, module)?)?;
    Ok(())
}
