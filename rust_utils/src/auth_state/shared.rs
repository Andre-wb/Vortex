use std::sync::Arc;

use once_cell::sync::Lazy;
use parking_lot::RwLock;
use vortex_auth::entry::service::EntryRateService;
use vortex_auth::handoff::memory::MemoryReplayGuard;
use vortex_auth::handoff::service::ReplayService;
use vortex_auth::login::service::LoginChallengeService;
use vortex_auth::passkey::service::PasskeyService;
use vortex_auth::ports::clock::Clock;
use vortex_auth::ports::denylist::Denylist;
use vortex_auth::ports::entropy::Entropy;
use vortex_auth::ports::login_challenges::LoginChallenges;
use vortex_auth::ports::passkey_challenges::PasskeyChallenges;
use vortex_auth::ports::password_markers::PasswordMarkers;
use vortex_auth::ports::qr_sessions::QrSessions;
use vortex_auth::ports::replay::ReplayGuard;
use vortex_auth::ports::wallet_challenges::WalletChallenges;
use vortex_auth::qr::service::QrLoginService;
use vortex_auth::random::system_entropy::SystemEntropy;
use vortex_auth::revocation::service::RevocationService;
use vortex_auth::second_factor::service::SecondFactorService;
use vortex_auth::time::system_clock::SystemClock;
use vortex_auth::totp::service::TotpRateService;
use vortex_auth::wallet::service::WalletLinkService;
use vortex_ratelimit::ports::attempt_limiter::AttemptLimiter;
use vortex_redis::backbone::RedisBackbone;
use vortex_redis::config::RedisConfig;
use vortex_redis::error::BackboneError;

use crate::auth_state::stores::Stores;

pub const MEMORY: &str = "memory";
pub const REDIS: &str = "redis";
pub const UNAVAILABLE: &str = "unavailable";

static MODE: Lazy<RwLock<&'static str>> = Lazy::new(|| RwLock::new(MEMORY));

static REVOCATION: Lazy<RwLock<Arc<RevocationService>>> =
    Lazy::new(|| RwLock::new(Arc::new(build_revocation(Stores::in_memory().denylist))));

static SECOND_FACTOR: Lazy<RwLock<Arc<SecondFactorService>>> =
    Lazy::new(|| RwLock::new(Arc::new(build_second_factor(Stores::in_memory().markers))));

static REPLAY: Lazy<RwLock<Arc<ReplayService>>> =
    Lazy::new(|| RwLock::new(Arc::new(build_replay(Stores::in_memory().replay))));

static LOGIN: Lazy<RwLock<Arc<LoginChallengeService>>> =
    Lazy::new(|| RwLock::new(Arc::new(build_login(Stores::in_memory().login))));

static QR: Lazy<RwLock<Arc<QrLoginService>>> = Lazy::new(|| {
    RwLock::new(Arc::new(build_qr(
        LOGIN.read().clone(),
        Stores::in_memory().qr,
    )))
});

static PASSKEY: Lazy<RwLock<Arc<PasskeyService>>> =
    Lazy::new(|| RwLock::new(Arc::new(build_passkey(Stores::in_memory().passkey))));

static WALLET_LINK: Lazy<RwLock<Arc<WalletLinkService>>> =
    Lazy::new(|| RwLock::new(Arc::new(build_wallet_link(Stores::in_memory().wallet))));

static ENTRY_RATE: Lazy<RwLock<Arc<EntryRateService>>> =
    Lazy::new(|| RwLock::new(Arc::new(build_entry_rate(Stores::in_memory().attempts))));

static TOTP_RATE: Lazy<RwLock<Arc<TotpRateService>>> =
    Lazy::new(|| RwLock::new(Arc::new(build_totp_rate(Stores::in_memory().attempts))));

fn clock() -> Arc<dyn Clock> {
    Arc::new(SystemClock::new())
}

fn entropy() -> Arc<dyn Entropy> {
    Arc::new(SystemEntropy::new())
}

fn build_revocation(denylist: Arc<dyn Denylist>) -> RevocationService {
    RevocationService::new(denylist, clock())
}

fn build_second_factor(markers: Arc<dyn PasswordMarkers>) -> SecondFactorService {
    SecondFactorService::new(markers, clock())
}

fn build_replay(guard: Arc<dyn ReplayGuard>) -> ReplayService {
    ReplayService::new(guard, clock())
}

fn build_login(challenges: Arc<dyn LoginChallenges>) -> LoginChallengeService {
    LoginChallengeService::new(challenges, clock(), entropy())
}

fn build_qr(
    challenges: Arc<LoginChallengeService>,
    sessions: Arc<dyn QrSessions>,
) -> QrLoginService {
    QrLoginService::new(challenges, sessions, clock(), entropy())
}

fn build_passkey(challenges: Arc<dyn PasskeyChallenges>) -> PasskeyService {
    PasskeyService::new(challenges, clock(), entropy())
}

fn build_wallet_link(challenges: Arc<dyn WalletChallenges>) -> WalletLinkService {
    WalletLinkService::new(challenges, clock(), entropy())
}

fn build_entry_rate(attempts: Arc<dyn AttemptLimiter>) -> EntryRateService {
    EntryRateService::new(attempts, clock())
}

fn build_totp_rate(attempts: Arc<dyn AttemptLimiter>) -> TotpRateService {
    TotpRateService::new(attempts, clock())
}

fn install(stores: Stores, mode: &'static str) {
    let login = Arc::new(build_login(stores.login));
    *REVOCATION.write() = Arc::new(build_revocation(stores.denylist));
    *SECOND_FACTOR.write() = Arc::new(build_second_factor(stores.markers));
    *REPLAY.write() = Arc::new(build_replay(stores.replay));
    *LOGIN.write() = login.clone();
    *QR.write() = Arc::new(build_qr(login, stores.qr));
    *PASSKEY.write() = Arc::new(build_passkey(stores.passkey));
    *WALLET_LINK.write() = Arc::new(build_wallet_link(stores.wallet));
    *ENTRY_RATE.write() = Arc::new(build_entry_rate(stores.attempts.clone()));
    *TOTP_RATE.write() = Arc::new(build_totp_rate(stores.attempts));
    *MODE.write() = mode;
}

pub fn revocation() -> Arc<RevocationService> {
    REVOCATION.read().clone()
}

pub fn second_factor() -> Arc<SecondFactorService> {
    SECOND_FACTOR.read().clone()
}

pub fn replay() -> Arc<ReplayService> {
    REPLAY.read().clone()
}

pub fn login_challenges() -> Arc<LoginChallengeService> {
    LOGIN.read().clone()
}

pub fn qr_login() -> Arc<QrLoginService> {
    QR.read().clone()
}

pub fn passkey() -> Arc<PasskeyService> {
    PASSKEY.read().clone()
}

pub fn wallet_link() -> Arc<WalletLinkService> {
    WALLET_LINK.read().clone()
}

pub fn entry_rate() -> Arc<EntryRateService> {
    ENTRY_RATE.read().clone()
}

pub fn totp_rate() -> Arc<TotpRateService> {
    TOTP_RATE.read().clone()
}

pub fn forget_replay_in_memory() -> bool {
    if mode() != MEMORY {
        return false;
    }
    *REPLAY.write() = Arc::new(build_replay(Arc::new(MemoryReplayGuard::new())));
    true
}

pub fn mode() -> &'static str {
    *MODE.read()
}

pub fn is_shared() -> bool {
    mode() == REDIS
}

pub fn connect(config: RedisConfig) -> Result<(), BackboneError> {
    let backbone: Arc<RedisBackbone> = match RedisBackbone::connect(config) {
        Ok(backbone) => backbone,
        Err(BackboneError::Unconfigured) => return Err(BackboneError::Unconfigured),
        Err(error) => {
            seal_off();
            return Err(error);
        }
    };

    install(Stores::in_redis(backbone), REDIS);
    Ok(())
}

pub fn seal_off() {
    install(Stores::sealed(), UNAVAILABLE);
}
