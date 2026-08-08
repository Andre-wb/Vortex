use crate::censorship::refusal::Refusal;
use crate::censorship::region::Region;
use crate::censorship::report::Report;

pub trait ReportStore: Send + Sync {
    fn submit(&self, region: &Region, report: &Report) -> Result<(), Refusal>;

    fn reports(&self, region: &Region) -> Vec<Report>;

    fn regions(&self) -> Vec<Region>;

    fn len(&self) -> usize {
        self.regions().len()
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
