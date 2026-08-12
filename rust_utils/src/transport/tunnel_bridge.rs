use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use vortex_transport::dga::generator::DomainGenerator;
use vortex_transport::dns::{answer, query};
use vortex_transport::doh::resolver::Resolvers;
use vortex_transport::doh::tunnel::DohTunnel;

#[pyclass(module = "vortex_chat", name = "DomainGenerator")]
pub struct PyDomainGenerator {
    generator: DomainGenerator,
}

#[pymethods]
impl PyDomainGenerator {
    #[new]
    fn new(seed: &str) -> Self {
        PyDomainGenerator {
            generator: DomainGenerator::seeded(seed),
        }
    }

    fn on(&self, day: &str, count: usize) -> Vec<String> {
        self.generator.on(day, count)
    }

    fn current(&self, now: i64, count: usize) -> Vec<String> {
        self.generator.current(now, count)
    }
}

#[pyclass(module = "vortex_chat", name = "DohTunnel")]
pub struct PyDohTunnel {
    tunnel: DohTunnel,
    resolvers: Resolvers,
}

#[pymethods]
impl PyDohTunnel {
    #[new]
    fn new(suffix: &str) -> PyResult<Self> {
        let tunnel = DohTunnel::under(suffix).ok_or_else(|| {
            PyValueError::new_err(format!(
                "суффикс не оставляет места под данные в имени DNS: {suffix}"
            ))
        })?;
        Ok(PyDohTunnel {
            tunnel,
            resolvers: Resolvers::default(),
        })
    }

    #[getter]
    fn suffix(&self) -> &str {
        self.tunnel.suffix()
    }

    #[getter]
    fn payload_per_query(&self) -> usize {
        self.tunnel.payload_per_query()
    }

    #[getter]
    fn resolver_count(&self) -> usize {
        self.resolvers.len()
    }

    fn next_resolver(&self) -> Option<&str> {
        self.resolvers.take()
    }

    #[pyo3(signature = (data, message=0))]
    fn encode(&self, data: &[u8], message: u16) -> PyResult<Vec<String>> {
        self.tunnel
            .encode(data, message)
            .ok_or_else(|| PyValueError::new_err("сообщение не помещается в поле номера куска"))
    }

    fn decode(&self, fqdn: &str) -> Option<(u16, u16, u16, Vec<u8>)> {
        self.tunnel
            .decode(fqdn)
            .map(|(chunk, payload)| (chunk.message, chunk.total, chunk.index, payload))
    }
}

#[pyfunction]
#[pyo3(signature = (host, kind=query::TYPE_A))]
pub fn dns_query(host: &str, kind: u16) -> PyResult<Vec<u8>> {
    query::asking(host, kind)
        .ok_or_else(|| PyValueError::new_err(format!("имя непредставимо в DNS: {host}")))
}

#[pyfunction]
pub fn dns_addresses(wire: &[u8]) -> Vec<String> {
    answer::addresses(wire)
        .into_iter()
        .map(|address| address.to_string())
        .collect()
}
