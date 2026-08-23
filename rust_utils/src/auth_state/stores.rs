use std::sync::Arc;

use vortex_auth::handoff::memory::MemoryReplayGuard;
use vortex_auth::handoff::unavailable::UnavailableReplayGuard;
use vortex_auth::login::memory::MemoryLoginChallenges;
use vortex_auth::login::unavailable::UnavailableLoginChallenges;
use vortex_auth::passkey::memory::MemoryPasskeyChallenges;
use vortex_auth::passkey::unavailable::UnavailablePasskeyChallenges;
use vortex_auth::ports::denylist::Denylist;
use vortex_auth::ports::login_challenges::LoginChallenges;
use vortex_auth::ports::passkey_challenges::PasskeyChallenges;
use vortex_auth::ports::password_markers::PasswordMarkers;
use vortex_auth::ports::qr_sessions::QrSessions;
use vortex_auth::ports::replay::ReplayGuard;
use vortex_auth::ports::wallet_challenges::WalletChallenges;
use vortex_auth::qr::memory::MemoryQrSessions;
use vortex_auth::qr::unavailable::UnavailableQrSessions;
use vortex_auth::revocation::memory::MemoryDenylist;
use vortex_auth::revocation::unavailable::UnavailableDenylist;
use vortex_auth::second_factor::memory::MemoryPasswordMarkers;
use vortex_auth::second_factor::unavailable::UnavailablePasswordMarkers;
use vortex_auth::wallet::memory::MemoryWalletChallenges;
use vortex_auth::wallet::unavailable::UnavailableWalletChallenges;
use vortex_ratelimit::attempt::memory::MemoryAttemptLimiter;
use vortex_ratelimit::attempt::unavailable::UnavailableAttemptLimiter;
use vortex_ratelimit::ports::attempt_limiter::AttemptLimiter;
use vortex_redis::auth::denylist::RedisDenylist;
use vortex_redis::auth::login_challenges::RedisLoginChallenges;
use vortex_redis::auth::passkey_challenges::RedisPasskeyChallenges;
use vortex_redis::auth::password_markers::RedisPasswordMarkers;
use vortex_redis::auth::qr_sessions::RedisQrSessions;
use vortex_redis::auth::replay::RedisReplayGuard;
use vortex_redis::auth::wallet_challenges::RedisWalletChallenges;
use vortex_redis::backbone::RedisBackbone;
use vortex_redis::ratelimit::attempt_limiter::RedisAttemptLimiter;

pub struct Stores {
    pub attempts: Arc<dyn AttemptLimiter>,
    pub denylist: Arc<dyn Denylist>,
    pub markers: Arc<dyn PasswordMarkers>,
    pub replay: Arc<dyn ReplayGuard>,
    pub login: Arc<dyn LoginChallenges>,
    pub qr: Arc<dyn QrSessions>,
    pub passkey: Arc<dyn PasskeyChallenges>,
    pub wallet: Arc<dyn WalletChallenges>,
}

impl Stores {
    pub fn in_memory() -> Self {
        Stores {
            attempts: Arc::new(MemoryAttemptLimiter::new()),
            denylist: Arc::new(MemoryDenylist::new()),
            markers: Arc::new(MemoryPasswordMarkers::new()),
            replay: Arc::new(MemoryReplayGuard::new()),
            login: Arc::new(MemoryLoginChallenges::new()),
            qr: Arc::new(MemoryQrSessions::new()),
            passkey: Arc::new(MemoryPasskeyChallenges::new()),
            wallet: Arc::new(MemoryWalletChallenges::new()),
        }
    }

    pub fn sealed() -> Self {
        Stores {
            attempts: Arc::new(UnavailableAttemptLimiter::new()),
            denylist: Arc::new(UnavailableDenylist::new()),
            markers: Arc::new(UnavailablePasswordMarkers::new()),
            replay: Arc::new(UnavailableReplayGuard::new()),
            login: Arc::new(UnavailableLoginChallenges::new()),
            qr: Arc::new(UnavailableQrSessions::new()),
            passkey: Arc::new(UnavailablePasskeyChallenges::new()),
            wallet: Arc::new(UnavailableWalletChallenges::new()),
        }
    }

    pub fn in_redis(backbone: Arc<RedisBackbone>) -> Self {
        Stores {
            attempts: Arc::new(RedisAttemptLimiter::for_auth(backbone.clone())),
            denylist: Arc::new(RedisDenylist::new(backbone.clone())),
            markers: Arc::new(RedisPasswordMarkers::new(backbone.clone())),
            replay: Arc::new(RedisReplayGuard::new(backbone.clone())),
            login: Arc::new(RedisLoginChallenges::new(backbone.clone())),
            qr: Arc::new(RedisQrSessions::new(backbone.clone())),
            passkey: Arc::new(RedisPasskeyChallenges::new(backbone.clone())),
            wallet: Arc::new(RedisWalletChallenges::new(backbone)),
        }
    }
}
