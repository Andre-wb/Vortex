use std::sync::Arc;

use vortex_auth::handoff::memory::MemoryReplayGuard;
use vortex_auth::login::memory::MemoryLoginChallenges;
use vortex_auth::passkey::memory::MemoryPasskeyChallenges;
use vortex_auth::ports::denylist::Denylist;
use vortex_auth::ports::login_challenges::LoginChallenges;
use vortex_auth::ports::passkey_challenges::PasskeyChallenges;
use vortex_auth::ports::password_markers::PasswordMarkers;
use vortex_auth::ports::qr_sessions::QrSessions;
use vortex_auth::ports::replay::ReplayGuard;
use vortex_auth::ports::wallet_challenges::WalletChallenges;
use vortex_auth::qr::memory::MemoryQrSessions;
use vortex_auth::revocation::memory::MemoryDenylist;
use vortex_auth::second_factor::memory::MemoryPasswordMarkers;
use vortex_auth::testing::{
    denylist_conformance, login_challenges_conformance, passkey_challenges_conformance,
    password_markers_conformance, qr_sessions_conformance, replay_conformance,
    wallet_challenges_conformance,
};
use vortex_auth::wallet::memory::MemoryWalletChallenges;

#[test]
fn the_denylist_in_memory_satisfies_the_port_contract() {
    let make = || -> Arc<dyn Denylist> { Arc::new(MemoryDenylist::new()) };
    denylist_conformance::check_all(&make);
}

#[test]
fn the_password_markers_in_memory_satisfy_the_port_contract() {
    let make = || -> Arc<dyn PasswordMarkers> { Arc::new(MemoryPasswordMarkers::new()) };
    password_markers_conformance::check_all(&make);
}

#[test]
fn the_replay_guard_in_memory_satisfies_the_port_contract() {
    let make = || -> Arc<dyn ReplayGuard> { Arc::new(MemoryReplayGuard::new()) };
    replay_conformance::check_all(&make);
}

#[test]
fn the_wallet_challenges_in_memory_satisfy_the_port_contract() {
    let make = || -> Arc<dyn WalletChallenges> { Arc::new(MemoryWalletChallenges::new()) };
    wallet_challenges_conformance::check_all(&make);
}

#[test]
fn the_passkey_challenges_in_memory_satisfy_the_port_contract() {
    let make = || -> Arc<dyn PasskeyChallenges> { Arc::new(MemoryPasskeyChallenges::new()) };
    passkey_challenges_conformance::check_all(&make);
}

#[test]
fn the_login_challenges_in_memory_satisfy_the_port_contract() {
    let make = || -> Arc<dyn LoginChallenges> { Arc::new(MemoryLoginChallenges::new()) };
    login_challenges_conformance::check_all(&make);
}

#[test]
fn the_qr_sessions_in_memory_satisfy_the_port_contract() {
    let make = || -> Arc<dyn QrSessions> { Arc::new(MemoryQrSessions::new()) };
    qr_sessions_conformance::check_all(&make);
}
