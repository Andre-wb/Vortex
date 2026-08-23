use std::sync::Arc;

use vortex_redis::backbone::RedisBackbone;
use vortex_redis::resume::session_cursors::RedisSessionCursors;
use vortex_redis::resume::upload_sessions::RedisUploadSessions;
use vortex_resume::cursor::memory::MemorySessionCursors;
use vortex_resume::cursor::unavailable::UnavailableSessionCursors;
use vortex_resume::ports::session_cursors::SessionCursors;
use vortex_resume::ports::upload_sessions::UploadSessions;
use vortex_resume::upload::memory::MemoryUploadSessions;
use vortex_resume::upload::unavailable::UnavailableUploadSessions;

pub struct Stores {
    pub uploads: Arc<dyn UploadSessions>,
    pub cursors: Arc<dyn SessionCursors>,
}

impl Stores {
    pub fn in_memory() -> Self {
        Stores {
            uploads: Arc::new(MemoryUploadSessions::new()),
            cursors: Arc::new(MemorySessionCursors::new()),
        }
    }

    pub fn in_redis(backbone: Arc<RedisBackbone>) -> Self {
        Stores {
            uploads: Arc::new(RedisUploadSessions::new(backbone.clone())),
            cursors: Arc::new(RedisSessionCursors::new(backbone)),
        }
    }

    pub fn sealed() -> Self {
        Stores {
            uploads: Arc::new(UnavailableUploadSessions::new()),
            cursors: Arc::new(UnavailableSessionCursors::new()),
        }
    }
}
