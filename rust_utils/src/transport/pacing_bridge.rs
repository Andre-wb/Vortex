use pyo3::prelude::*;
use vortex_transport::burst::plan::BurstPlan;
use vortex_transport::loss::fate::LossProfile;
use vortex_transport::random::os_random::OsRandom;
use vortex_transport::rotation::schedule::RotationSchedule;

#[pyclass(module = "vortex_chat", name = "BurstPlan")]
pub struct PyBurstPlan {
    plan: BurstPlan,
    random: OsRandom,
}

#[pymethods]
impl PyBurstPlan {
    #[new]
    #[pyo3(signature = (burst_size=None, pause_min=None, pause_max=None))]
    fn new(burst_size: Option<usize>, pause_min: Option<f64>, pause_max: Option<f64>) -> Self {
        let mut plan = BurstPlan::default();
        if let Some(size) = burst_size {
            plan = plan.burst_size(size);
        }
        if let (Some(low), Some(high)) = (pause_min, pause_max) {
            plan = plan.pause_between(low, high);
        }
        PyBurstPlan {
            plan,
            random: OsRandom::new(),
        }
    }

    #[getter]
    fn burst_size(&self) -> usize {
        self.plan.burst_size
    }

    #[getter]
    fn gather(&self) -> f64 {
        self.plan.gather
    }

    fn room_left(&self, gathered: usize) -> usize {
        self.plan.room_left(gathered)
    }

    fn gap(&self) -> f64 {
        self.plan.gap(&self.random)
    }

    fn pause(&self) -> f64 {
        self.plan.pause(&self.random)
    }
}

#[pyclass(module = "vortex_chat", name = "PacketLoss")]
pub struct PyPacketLoss {
    profile: LossProfile,
    random: OsRandom,
}

#[pymethods]
impl PyPacketLoss {
    #[new]
    #[pyo3(signature = (loss_rate=None, duplicate_rate=None))]
    fn new(loss_rate: Option<f64>, duplicate_rate: Option<f64>) -> Self {
        let profile = match (loss_rate, duplicate_rate) {
            (Some(loss), Some(duplicate)) => LossProfile::of(loss, duplicate),
            (Some(loss), None) => LossProfile::of(loss, LossProfile::default().duplicate_rate),
            (None, Some(duplicate)) => LossProfile::of(LossProfile::default().loss_rate, duplicate),
            (None, None) => LossProfile::default(),
        };
        PyPacketLoss {
            profile,
            random: OsRandom::new(),
        }
    }

    #[getter]
    fn loss_rate(&self) -> f64 {
        self.profile.loss_rate
    }

    #[getter]
    fn duplicate_rate(&self) -> f64 {
        self.profile.duplicate_rate
    }

    fn decide(&self) -> Vec<f64> {
        self.profile.decide(&self.random).copies()
    }
}

#[pyclass(module = "vortex_chat", name = "RotationSchedule")]
pub struct PyRotationSchedule {
    schedule: RotationSchedule,
    random: OsRandom,
}

#[pymethods]
impl PyRotationSchedule {
    #[new]
    #[pyo3(signature = (min_interval=None, max_interval=None))]
    fn new(min_interval: Option<f64>, max_interval: Option<f64>) -> Self {
        let schedule = match (min_interval, max_interval) {
            (Some(low), Some(high)) => RotationSchedule::between(low, high),
            _ => RotationSchedule::default(),
        };
        PyRotationSchedule {
            schedule,
            random: OsRandom::new(),
        }
    }

    #[getter]
    fn min_interval(&self) -> f64 {
        self.schedule.min_interval
    }

    #[getter]
    fn max_interval(&self) -> f64 {
        self.schedule.max_interval
    }

    fn next_wait(&self) -> f64 {
        self.schedule.next_wait(&self.random)
    }
}
