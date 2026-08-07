use std::sync::OnceLock;

use fred::prelude::*;

pub struct LuaScript {
    source: &'static str,
    sha: OnceLock<String>,
}

impl LuaScript {
    pub const fn new(source: &'static str) -> Self {
        LuaScript {
            source,
            sha: OnceLock::new(),
        }
    }

    pub fn source(&self) -> &'static str {
        self.source
    }

    async fn sha(&self, pool: &Pool) -> Result<String, Error> {
        if let Some(sha) = self.sha.get() {
            return Ok(sha.clone());
        }
        let sha: String = pool.script_load(self.source).await?;
        let _ = self.sha.set(sha.clone());
        Ok(sha)
    }

    pub async fn run<R>(&self, pool: &Pool, keys: Vec<String>, args: Vec<Value>) -> Result<R, Error>
    where
        R: FromValue,
    {
        let sha = self.sha(pool).await?;
        match pool.evalsha(&sha, keys.clone(), args.clone()).await {
            Ok(value) => Ok(value),
            Err(err) if err.details().contains("NOSCRIPT") => {
                pool.eval(self.source, keys, args).await
            }
            Err(err) => Err(err),
        }
    }
}
