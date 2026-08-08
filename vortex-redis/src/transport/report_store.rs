use std::sync::Arc;

use fred::prelude::*;
use vortex_transport::censorship::config::DashboardConfig;
use vortex_transport::censorship::refusal::Refusal;
use vortex_transport::censorship::region::Region;
use vortex_transport::censorship::report::Report;
use vortex_transport::censorship::store::memory_reports::MemoryReportStore;
use vortex_transport::ports::report_store::ReportStore;

use crate::backbone::RedisBackbone;
use crate::keys::KeySpace;
use crate::script::LuaScript;

const DOMAIN: &str = "censorship";
const REGION_INDEX: &str = "regions";
const REPORTS: &str = "reports";

static SUBMIT: LuaScript = LuaScript::new(
    r#"
local max_regions = tonumber(ARGV[1])
local max_reports = tonumber(ARGV[2])
local region = ARGV[3]
local report = ARGV[4]
if redis.call('SISMEMBER', KEYS[1], region) == 0 then
  if redis.call('SCARD', KEYS[1]) >= max_regions then
    return 0
  end
  redis.call('SADD', KEYS[1], region)
end
redis.call('RPUSH', KEYS[2], report)
redis.call('LTRIM', KEYS[2], -max_reports, -1)
return 1
"#,
);

pub struct RedisReportStore {
    backbone: Arc<RedisBackbone>,
    fallback: Arc<MemoryReportStore>,
    config: DashboardConfig,
    space: KeySpace,
}

impl RedisReportStore {
    pub fn new(backbone: Arc<RedisBackbone>) -> Self {
        RedisReportStore::with_config(backbone, DashboardConfig::default())
    }

    pub fn with_config(backbone: Arc<RedisBackbone>, config: DashboardConfig) -> Self {
        let space = backbone.key_space(DOMAIN);
        RedisReportStore {
            backbone,
            fallback: Arc::new(MemoryReportStore::new(config)),
            config,
            space,
        }
    }

    fn index_key(&self) -> String {
        self.space.key(REGION_INDEX)
    }

    fn reports_key(&self, region: &Region) -> String {
        self.space.member_key(REPORTS, region.as_str())
    }
}

impl ReportStore for RedisReportStore {
    fn submit(&self, region: &Region, report: &Report) -> Result<(), Refusal> {
        let index = self.index_key();
        let reports = self.reports_key(region);
        let name = region.as_str().to_owned();
        let encoded = report.encode();
        let max_regions = self.config.max_regions as i64;
        let max_reports = self.config.max_reports_per_region.max(1) as i64;

        let stored = self.backbone.execute("запись отчёта о блокировках", {
            move |pool| {
                let keys = vec![index.clone(), reports.clone()];
                let args: Vec<Value> = vec![
                    max_regions.into(),
                    max_reports.into(),
                    name.clone().into(),
                    encoded.clone().into(),
                ];
                async move { SUBMIT.run::<i64>(&pool, keys, args).await }
            }
        });

        match stored {
            Ok(1) => Ok(()),
            Ok(_) => Err(Refusal::AtCapacity),
            Err(_) => self.fallback.submit(region, report),
        }
    }

    fn reports(&self, region: &Region) -> Vec<Report> {
        let key = self.reports_key(region);
        let stored =
            self.backbone
                .execute("чтение отчётов региона", move |pool| {
                    let key = key.clone();
                    async move { pool.lrange::<Vec<String>, _>(key, 0, -1).await }
                });

        let mut held: Vec<Report> = stored
            .unwrap_or_default()
            .iter()
            .filter_map(|line| Report::decode(line))
            .collect();
        held.extend(self.fallback.reports(region));
        held.sort_by(|left, right| {
            left.received_at
                .partial_cmp(&right.received_at)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        held
    }

    fn regions(&self) -> Vec<Region> {
        let index = self.index_key();
        let stored =
            self.backbone
                .execute("список регионов панели", move |pool| {
                    let index = index.clone();
                    async move { pool.smembers::<Vec<String>, _>(index).await }
                });

        let mut names: Vec<Region> = stored
            .unwrap_or_default()
            .iter()
            .filter_map(|name| Region::parse(name))
            .collect();
        names.extend(self.fallback.regions());
        names.sort();
        names.dedup();
        names
    }
}
