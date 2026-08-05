//! Python-класс `WafEngine` — обёртка над фасадом крейта.

use crate::interop::facade::WafFacade;
use crate::interop::finding_map::FlatMap;
use crate::python::extract;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::collections::BTreeMap;

#[pyclass(module = "vortex_waf", name = "WafEngine")]
pub struct PyWafEngine {
    facade: WafFacade,
}

#[pymethods]
impl PyWafEngine {
    /// Настройки принимаются словарём; отсутствующие ключи берут умолчания.
    #[new]
    #[pyo3(signature = (config=None))]
    fn new(config: Option<&Bound<'_, PyDict>>) -> PyResult<Self> {
        WafFacade::new(&extract::config_spec(config))
            .map(|facade| PyWafEngine { facade })
            .map_err(|err| PyRuntimeError::new_err(err.to_string()))
    }

    /// Полный анализ запроса. Возвращает словарь с ключами `block`, `reason`,
    /// `findings`, `matched_rules`, `client_ip`.
    fn analyze_request<'py>(
        &self,
        py: Python<'py>,
        request: &Bound<'py, PyDict>,
    ) -> PyResult<Bound<'py, PyDict>> {
        let view = self.facade.analyze(extract::request_spec(request));
        let out = PyDict::new(py);
        out.set_item("block", view.block)?;
        out.set_item("reason", view.reason)?;
        out.set_item("findings", flat_maps_to_py(py, &view.findings)?)?;
        out.set_item("matched_rules", view.matched_rules)?;
        out.set_item("client_ip", view.client_ip)?;
        Ok(out)
    }

    fn is_ip_blocked(&self, ip: &str) -> bool {
        self.facade.is_ip_blocked(ip)
    }

    #[pyo3(signature = (ip, reason="Manual block", duration=None))]
    fn block_ip(&self, ip: &str, reason: &str, duration: Option<u64>) -> bool {
        let duration = duration.unwrap_or(self.facade.config().block_duration_secs);
        self.facade.block_ip(ip, reason, duration)
    }

    fn unblock_ip(&self, ip: &str) -> bool {
        self.facade.unblock_ip(ip)
    }

    fn blocked_ips<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let items: Vec<Bound<'py, PyDict>> = self
            .facade
            .blocked_ips()
            .into_iter()
            .map(|view| {
                let dict = PyDict::new(py);
                dict.set_item("ip", view.ip)?;
                dict.set_item("blocked_at", view.blocked_at)?;
                dict.set_item("blocked_until", view.blocked_until)?;
                dict.set_item("reason", view.reason)?;
                dict.set_item("duration", view.duration)?;
                Ok(dict)
            })
            .collect::<PyResult<_>>()?;
        PyList::new(py, items)
    }

    fn add_whitelist_ip(&self, ip: &str) -> bool {
        self.facade.add_whitelist_ip(ip)
    }

    fn remove_whitelist_ip(&self, ip: &str) -> bool {
        self.facade.remove_whitelist_ip(ip)
    }

    fn whitelist(&self) -> Vec<String> {
        self.facade.whitelist()
    }

    fn add_blacklist_ip(&self, ip: &str) -> bool {
        self.facade.add_blacklist_ip(ip)
    }

    fn remove_blacklist_ip(&self, ip: &str) -> bool {
        self.facade.remove_blacklist_ip(ip)
    }

    fn blacklist(&self) -> Vec<String> {
        self.facade.blacklist()
    }

    fn get_stats<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let stats = self.facade.stats();
        let triggered = PyDict::new(py);
        for (rule_id, count) in &stats.rules_triggered {
            triggered.set_item(rule_id, count)?;
        }

        let out = PyDict::new(py);
        out.set_item("total_requests", stats.total_requests)?;
        out.set_item("blocked_requests", stats.blocked_requests)?;
        out.set_item("block_rate", stats.block_rate)?;
        out.set_item("rules_triggered", triggered)?;
        out.set_item("ip_blocks", stats.ip_blocks)?;
        out.set_item("blocked_ips_count", stats.blocked_ips_count)?;
        out.set_item("active_rules", stats.active_rules)?;
        out.set_item("rules_loaded", stats.rules_loaded)?;
        Ok(out)
    }

    fn rules<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let items: Vec<Bound<'py, PyDict>> = self
            .facade
            .rules()
            .into_iter()
            .map(|view| {
                let dict = PyDict::new(py);
                dict.set_item("id", view.id)?;
                dict.set_item("description", view.description)?;
                dict.set_item("severity", view.severity)?;
                dict.set_item("action", view.action)?;
                dict.set_item("trigger_count", view.trigger_count)?;
                dict.set_item("last_triggered", view.last_triggered)?;
                Ok(dict)
            })
            .collect::<PyResult<_>>()?;
        PyList::new(py, items)
    }

    /// Удаляет просроченные блокировки и историю неактивных адресов.
    fn run_maintenance(&self) -> usize {
        self.facade.run_maintenance()
    }

    /// Новая задача-капча. Выдача и проверка живут на одном экземпляре, поэтому
    /// подписаны общим ключом.
    #[pyo3(signature = (client_ip="unknown"))]
    fn generate_captcha<'py>(
        &self,
        py: Python<'py>,
        client_ip: &str,
    ) -> PyResult<Bound<'py, PyDict>> {
        let (challenge_id, question, expires_in) = self.facade.issue_captcha(client_ip);
        let dict = PyDict::new(py);
        dict.set_item("challenge_id", challenge_id)?;
        dict.set_item("question", question)?;
        dict.set_item("expires_in", expires_in)?;
        Ok(dict)
    }

    fn verify_captcha(&self, challenge_id: &str, answer: &str) -> bool {
        self.facade.verify_captcha(challenge_id, answer)
    }

    #[getter]
    fn rate_limit_requests(&self) -> usize {
        self.facade.config().rate_limit_requests
    }

    #[getter]
    fn rate_limit_window(&self) -> u64 {
        self.facade.config().rate_limit_window_secs
    }

    #[getter]
    fn block_duration(&self) -> u64 {
        self.facade.config().block_duration_secs
    }

    #[getter]
    fn max_content_length(&self) -> usize {
        self.facade.config().max_content_length
    }

    #[getter]
    fn rule_count(&self) -> usize {
        self.facade.rule_count()
    }

    fn __repr__(&self) -> String {
        format!(
            "<WafEngine rules={} rate_limit={}/{}s>",
            self.facade.rule_count(),
            self.facade.config().rate_limit_requests,
            self.facade.config().rate_limit_window_secs,
        )
    }
}

fn flat_maps_to_py<'py>(py: Python<'py>, maps: &[FlatMap]) -> PyResult<Bound<'py, PyList>> {
    let items: Vec<Bound<'py, PyDict>> = maps
        .iter()
        .map(|map| flat_map_to_py(py, map))
        .collect::<PyResult<_>>()?;
    PyList::new(py, items)
}

fn flat_map_to_py<'py>(
    py: Python<'py>,
    map: &BTreeMap<String, String>,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    for (key, value) in map {
        dict.set_item(key, value)?;
    }
    Ok(dict)
}
