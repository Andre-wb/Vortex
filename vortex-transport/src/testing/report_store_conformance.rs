use std::sync::Arc;

use crate::censorship::config::DashboardConfig;
use crate::censorship::refusal::Refusal;
use crate::censorship::region::Region;
use crate::censorship::report::Report;
use crate::ports::report_store::ReportStore;

pub type StoreFactory = dyn Fn(DashboardConfig) -> Arc<dyn ReportStore>;

pub fn region(name: &str) -> Region {
    Region::parse(name).unwrap()
}

pub fn report(transport: &str, ok: bool, at: f64) -> Report {
    Report::of(&[(transport.to_owned(), ok)], at).unwrap()
}

pub fn check_all(make: &StoreFactory) {
    a_submitted_report_comes_back_for_its_region(make);
    a_region_nobody_reported_holds_nothing(make);
    reports_come_back_in_the_order_they_arrived(make);
    a_region_holds_no_more_reports_than_it_was_given_room_for(make);
    the_reports_that_are_dropped_are_the_oldest_ones(make);
    a_new_region_is_refused_once_the_panel_is_full(make);
    a_known_region_still_accepts_reports_when_the_panel_is_full(make);
    every_region_that_reported_is_listed(make);
    regions_come_back_in_one_stable_order(make);
    regions_are_counted(make);
    the_verdicts_of_a_report_survive_the_store(make);
    one_region_never_sees_the_reports_of_another(make);
}

pub fn a_submitted_report_comes_back_for_its_region(make: &StoreFactory) {
    let store = make(DashboardConfig::default());
    store
        .submit(&region("ru"), &report("tor", false, 1.0))
        .unwrap();
    let held = store.reports(&region("ru"));
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].says("tor"), Some(false));
}

pub fn a_region_nobody_reported_holds_nothing(make: &StoreFactory) {
    let store = make(DashboardConfig::default());
    assert!(store.reports(&region("ru")).is_empty());
    assert!(store.is_empty());
}

pub fn reports_come_back_in_the_order_they_arrived(make: &StoreFactory) {
    let store = make(DashboardConfig::default());
    for tick in 0..5 {
        store
            .submit(&region("ru"), &report("tor", false, tick as f64))
            .unwrap();
    }
    let stamps: Vec<f64> = store
        .reports(&region("ru"))
        .iter()
        .map(|held| held.received_at)
        .collect();
    assert_eq!(stamps, vec![0.0, 1.0, 2.0, 3.0, 4.0]);
}

pub fn a_region_holds_no_more_reports_than_it_was_given_room_for(make: &StoreFactory) {
    let store = make(DashboardConfig::default().max_reports_per_region(3));
    for tick in 0..10 {
        store
            .submit(&region("ru"), &report("tor", false, tick as f64))
            .unwrap();
    }
    assert_eq!(store.reports(&region("ru")).len(), 3);
}

pub fn the_reports_that_are_dropped_are_the_oldest_ones(make: &StoreFactory) {
    let store = make(DashboardConfig::default().max_reports_per_region(2));
    for tick in 0..4 {
        store
            .submit(&region("ru"), &report("tor", false, tick as f64))
            .unwrap();
    }
    let stamps: Vec<f64> = store
        .reports(&region("ru"))
        .iter()
        .map(|held| held.received_at)
        .collect();
    assert_eq!(stamps, vec![2.0, 3.0]);
}

pub fn a_new_region_is_refused_once_the_panel_is_full(make: &StoreFactory) {
    let store = make(DashboardConfig::default().max_regions(2));
    store
        .submit(&region("ru"), &report("tor", false, 1.0))
        .unwrap();
    store
        .submit(&region("ir"), &report("tor", false, 1.0))
        .unwrap();
    assert_eq!(
        store.submit(&region("cn"), &report("tor", false, 1.0)),
        Err(Refusal::AtCapacity)
    );
    assert!(store.reports(&region("cn")).is_empty());
}

pub fn a_known_region_still_accepts_reports_when_the_panel_is_full(make: &StoreFactory) {
    let store = make(DashboardConfig::default().max_regions(1));
    store
        .submit(&region("ru"), &report("tor", false, 1.0))
        .unwrap();
    store
        .submit(&region("ru"), &report("tor", false, 2.0))
        .unwrap();
    assert_eq!(store.reports(&region("ru")).len(), 2);
}

pub fn every_region_that_reported_is_listed(make: &StoreFactory) {
    let store = make(DashboardConfig::default());
    for name in ["ru", "ir"] {
        store
            .submit(&region(name), &report("tor", false, 1.0))
            .unwrap();
    }
    let listed: Vec<String> = store
        .regions()
        .iter()
        .map(|held| held.as_str().to_owned())
        .collect();
    assert!(listed.contains(&"ru".to_owned()));
    assert!(listed.contains(&"ir".to_owned()));
}

pub fn regions_come_back_in_one_stable_order(make: &StoreFactory) {
    let store = make(DashboardConfig::default());
    for name in ["ru", "ir", "cn"] {
        store
            .submit(&region(name), &report("tor", false, 1.0))
            .unwrap();
    }
    assert_eq!(store.regions(), store.regions());
}

pub fn regions_are_counted(make: &StoreFactory) {
    let store = make(DashboardConfig::default());
    assert_eq!(store.len(), 0);
    store
        .submit(&region("ru"), &report("tor", false, 1.0))
        .unwrap();
    store
        .submit(&region("ru"), &report("tor", false, 2.0))
        .unwrap();
    assert_eq!(store.len(), 1);
    store
        .submit(&region("ir"), &report("tor", false, 1.0))
        .unwrap();
    assert_eq!(store.len(), 2);
}

pub fn the_verdicts_of_a_report_survive_the_store(make: &StoreFactory) {
    let store = make(DashboardConfig::default());
    let full = Report::of(
        &[
            ("tor".to_owned(), false),
            ("reality".to_owned(), true),
            ("sse".to_owned(), false),
        ],
        9.5,
    )
    .unwrap();
    store.submit(&region("ru"), &full).unwrap();
    let held = store.reports(&region("ru"));
    assert_eq!(held, vec![full]);
}

pub fn one_region_never_sees_the_reports_of_another(make: &StoreFactory) {
    let store = make(DashboardConfig::default());
    store
        .submit(&region("ru"), &report("tor", false, 1.0))
        .unwrap();
    store
        .submit(&region("ir"), &report("tor", true, 1.0))
        .unwrap();
    assert_eq!(store.reports(&region("ru"))[0].says("tor"), Some(false));
    assert_eq!(store.reports(&region("ir"))[0].says("tor"), Some(true));
}
