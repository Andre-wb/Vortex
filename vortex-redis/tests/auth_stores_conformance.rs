mod support;

use std::sync::Arc;

use vortex_auth::ports::denylist::Denylist;
use vortex_auth::ports::login_challenges::LoginChallenges;
use vortex_auth::ports::passkey_challenges::PasskeyChallenges;
use vortex_auth::ports::password_markers::PasswordMarkers;
use vortex_auth::ports::qr_sessions::QrSessions;
use vortex_auth::ports::replay::ReplayGuard;
use vortex_auth::ports::wallet_challenges::WalletChallenges;
use vortex_auth::testing::{
    denylist_conformance, login_challenges_conformance, passkey_challenges_conformance,
    password_markers_conformance, qr_sessions_conformance, replay_conformance,
    wallet_challenges_conformance,
};
use vortex_redis::auth::denylist::RedisDenylist;
use vortex_redis::auth::login_challenges::RedisLoginChallenges;
use vortex_redis::auth::passkey_challenges::RedisPasskeyChallenges;
use vortex_redis::auth::password_markers::RedisPasswordMarkers;
use vortex_redis::auth::qr_sessions::RedisQrSessions;
use vortex_redis::auth::replay::RedisReplayGuard;
use vortex_redis::auth::wallet_challenges::RedisWalletChallenges;

#[test]
fn the_redis_denylist_satisfies_the_same_port_contract() {
    if support::backbone(&support::unique_prefix("denylist-probe")).is_none() {
        eprintln!("Redis недоступен — проверка списка отозванных токенов пропущена");
        return;
    }
    let make = || -> Arc<dyn Denylist> {
        let prefix = support::unique_prefix("denylist");
        Arc::new(RedisDenylist::new(support::backbone(&prefix).unwrap()))
    };
    denylist_conformance::check_all(&make);
}

#[test]
fn the_redis_password_markers_satisfy_the_same_port_contract() {
    if support::backbone(&support::unique_prefix("markers-probe")).is_none() {
        eprintln!("Redis недоступен — проверка маркеров первого фактора пропущена");
        return;
    }
    let make = || -> Arc<dyn PasswordMarkers> {
        let prefix = support::unique_prefix("markers");
        Arc::new(RedisPasswordMarkers::new(
            support::backbone(&prefix).unwrap(),
        ))
    };
    password_markers_conformance::check_all(&make);
}

#[test]
fn the_redis_replay_guard_satisfies_the_same_port_contract() {
    if support::backbone(&support::unique_prefix("replay-probe")).is_none() {
        eprintln!("Redis недоступен — проверка защиты от повтора пропущена");
        return;
    }
    let make = || -> Arc<dyn ReplayGuard> {
        let prefix = support::unique_prefix("replay");
        Arc::new(RedisReplayGuard::new(support::backbone(&prefix).unwrap()))
    };
    replay_conformance::check_all(&make);
}

#[test]
fn the_redis_wallet_challenges_satisfy_the_same_port_contract() {
    if support::backbone(&support::unique_prefix("wallet-probe")).is_none() {
        eprintln!("Redis недоступен — проверка челленджей кошелька пропущена");
        return;
    }
    let make = || -> Arc<dyn WalletChallenges> {
        let prefix = support::unique_prefix("wallet");
        Arc::new(RedisWalletChallenges::new(
            support::backbone(&prefix).unwrap(),
        ))
    };
    wallet_challenges_conformance::check_all(&make);
}

#[test]
fn the_redis_passkey_challenges_satisfy_the_same_port_contract() {
    if support::backbone(&support::unique_prefix("passkey-probe")).is_none() {
        eprintln!("Redis недоступен — проверка челленджей passkey пропущена");
        return;
    }
    let make = || -> Arc<dyn PasskeyChallenges> {
        let prefix = support::unique_prefix("passkey");
        Arc::new(RedisPasskeyChallenges::new(
            support::backbone(&prefix).unwrap(),
        ))
    };
    passkey_challenges_conformance::check_all(&make);
}

#[test]
fn the_redis_login_challenges_satisfy_the_same_port_contract() {
    if support::backbone(&support::unique_prefix("login-probe")).is_none() {
        eprintln!("Redis недоступен — проверка челленджей входа пропущена");
        return;
    }
    let make = || -> Arc<dyn LoginChallenges> {
        let prefix = support::unique_prefix("login");
        Arc::new(RedisLoginChallenges::new(
            support::backbone(&prefix).unwrap(),
        ))
    };
    login_challenges_conformance::check_all(&make);
}

#[test]
fn the_redis_qr_sessions_satisfy_the_same_port_contract() {
    if support::backbone(&support::unique_prefix("qr-probe")).is_none() {
        eprintln!("Redis недоступен — проверка QR-сессий пропущена");
        return;
    }
    let make = || -> Arc<dyn QrSessions> {
        let prefix = support::unique_prefix("qr");
        Arc::new(RedisQrSessions::new(support::backbone(&prefix).unwrap()))
    };
    qr_sessions_conformance::check_all(&make);
}
