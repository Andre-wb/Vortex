use std::sync::Arc;
use tokio::sync::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::Value as JVal;

use crate::ast::Program;
use crate::error::{GravError, GravResult};
use crate::interpreter::{Interpreter, SharedState};
use crate::value::{BotCtx, BotOutput};

// ─────────────────────────────────────────────────────────────────────────────
// Telegram Bot API types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct ApiResponse<T> {
    ok:     bool,
    result: Option<T>,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Update {
    update_id:      i64,
    message:        Option<Message>,
    callback_query: Option<CallbackQuery>,
}

#[derive(Debug, Deserialize, Clone)]
struct CallbackQuery {
    id:      String,
    from:    User,
    message: Option<Message>,
    data:    Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Message {
    pub message_id: i64,
    pub from:       Option<User>,
    pub chat:       Chat,
    pub text:       Option<String>,
    pub photo:      Option<Vec<JVal>>,
    pub video:      Option<JVal>,
    pub voice:      Option<JVal>,
    pub document:   Option<JVal>,
    pub sticker:    Option<JVal>,
    pub audio:      Option<JVal>,
    pub animation:  Option<JVal>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct User {
    pub id:         i64,
    pub first_name: String,
    pub last_name:  Option<String>,
    pub username:   Option<String>,
    pub is_bot:     bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Chat {
    pub id: i64,
    #[serde(rename = "type", default)]
    pub type_: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Telegram client
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct TelegramClient {
    token:  String,
    client: reqwest::Client,
}

impl TelegramClient {
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token:  token.into(),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("reqwest client"),
        }
    }

    fn api_url(&self, method: &str) -> String {
        format!("https://api.telegram.org/bot{}/{}", self.token, method)
    }

    pub async fn get_updates(&self, offset: i64, timeout: u64) -> GravResult<Vec<Update>> {
        let resp: ApiResponse<Vec<Update>> = self.client
            .get(self.api_url("getUpdates"))
            .query(&[("offset", offset.to_string()), ("timeout", timeout.to_string())])
            .send().await?
            .json().await?;

        if !resp.ok {
            return Err(GravError::Bot(resp.description.unwrap_or_else(|| "getUpdates failed".into())));
        }
        Ok(resp.result.unwrap_or_default())
    }

    pub async fn send_message(&self, chat_id: i64, text: &str) -> GravResult<()> {
        let params = serde_json::json!({
            "chat_id":    chat_id,
            "text":       text,
            "parse_mode": "HTML",
        });
        let resp: ApiResponse<JVal> = self.client
            .post(self.api_url("sendMessage"))
            .json(&params)
            .send().await?
            .json().await?;

        if !resp.ok {
            eprintln!("[gravitix] sendMessage error: {}", resp.description.unwrap_or_default());
        }
        Ok(())
    }

    pub async fn send_chat_action(&self, chat_id: i64, action: &str) -> GravResult<()> {
        let params = serde_json::json!({ "chat_id": chat_id, "action": action });
        let _ = self.client.post(self.api_url("sendChatAction")).json(&params).send().await;
        Ok(())
    }

    pub async fn send_with_keyboard(
        &self,
        chat_id:  i64,
        text:     &str,
        buttons:  &[Vec<(String, String)>],
    ) -> GravResult<i64> {
        let inline_keyboard: Vec<Vec<JVal>> = buttons.iter().map(|row| {
            row.iter().map(|(label, data)| {
                serde_json::json!({ "text": label, "callback_data": data })
            }).collect()
        }).collect();
        let params = serde_json::json!({
            "chat_id":    chat_id,
            "text":       text,
            "parse_mode": "HTML",
            "reply_markup": { "inline_keyboard": inline_keyboard },
        });
        let resp: ApiResponse<JVal> = self.client
            .post(self.api_url("sendMessage"))
            .json(&params).send().await?.json().await?;
        if !resp.ok {
            eprintln!("[gravitix] send_with_keyboard error: {}", resp.description.unwrap_or_default());
            return Ok(0);
        }
        let msg_id = resp.result.as_ref()
            .and_then(|r| r.get("message_id"))
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        Ok(msg_id)
    }

    pub async fn edit_message(&self, chat_id: i64, msg_id: i64, text: &str) -> GravResult<()> {
        let params = serde_json::json!({
            "chat_id":    chat_id,
            "message_id": msg_id,
            "text":       text,
            "parse_mode": "HTML",
        });
        let resp: ApiResponse<JVal> = self.client
            .post(self.api_url("editMessageText"))
            .json(&params).send().await?.json().await?;
        if !resp.ok {
            eprintln!("[gravitix] editMessageText error: {}", resp.description.unwrap_or_default());
        }
        Ok(())
    }

    pub async fn answer_callback(&self, callback_id: &str, text: Option<&str>) -> GravResult<()> {
        let mut params = serde_json::json!({ "callback_query_id": callback_id });
        if let Some(t) = text {
            params["text"] = serde_json::Value::String(t.to_string());
        }
        let _ = self.client.post(self.api_url("answerCallbackQuery"))
            .json(&params).send().await;
        Ok(())
    }

    pub async fn get_me(&self) -> GravResult<User> {
        let resp: ApiResponse<User> = self.client
            .get(self.api_url("getMe"))
            .send().await?
            .json().await?;
        resp.result.ok_or_else(|| GravError::Bot("getMe failed".into()))
    }

    /// Send a media file (photo/document/audio/video/animation) by file_id or URL.
    /// Returns message_id on success.
    pub async fn send_media(
        &self,
        chat_id:  i64,
        kind:     &str,   // "photo" | "document" | "audio" | "video" | "animation"
        source:   &str,   // file_id or HTTPS URL
        caption:  Option<&str>,
    ) -> GravResult<i64> {
        let method = match kind {
            "document"  => "sendDocument",
            "audio"     => "sendAudio",
            "video"     => "sendVideo",
            "animation" => "sendAnimation",
            _           => "sendPhoto",
        };
        let media_key = match kind {
            "document"  => "document",
            "audio"     => "audio",
            "video"     => "video",
            "animation" => "animation",
            _           => "photo",
        };
        let mut params = serde_json::json!({
            "chat_id":    chat_id,
            media_key:    source,
            "parse_mode": "HTML",
        });
        if let Some(cap) = caption {
            params["caption"] = serde_json::Value::String(cap.to_string());
        }
        let resp: ApiResponse<JVal> = self.client
            .post(self.api_url(method))
            .json(&params).send().await?.json().await?;
        if !resp.ok {
            eprintln!("[gravitix] {} error: {}", method, resp.description.unwrap_or_default());
            return Ok(0);
        }
        Ok(resp.result.as_ref()
            .and_then(|r| r.get("message_id"))
            .and_then(|v| v.as_i64())
            .unwrap_or(0))
    }

    /// Forward a message from `from_chat` to `to_chat`.
    pub async fn forward_message(&self, to_chat: i64, from_chat: i64, msg_id: i64) -> GravResult<i64> {
        let params = serde_json::json!({
            "chat_id":      to_chat,
            "from_chat_id": from_chat,
            "message_id":   msg_id,
        });
        let resp: ApiResponse<JVal> = self.client
            .post(self.api_url("forwardMessage"))
            .json(&params).send().await?.json().await?;
        if !resp.ok {
            eprintln!("[gravitix] forwardMessage error: {}", resp.description.unwrap_or_default());
            return Ok(0);
        }
        Ok(resp.result.as_ref()
            .and_then(|r| r.get("message_id"))
            .and_then(|v| v.as_i64())
            .unwrap_or(0))
    }

    /// Get Telegram file info — returns (file_path, file_size).
    pub async fn get_file(&self, file_id: &str) -> GravResult<(String, u64)> {
        let params = serde_json::json!({ "file_id": file_id });
        let resp: ApiResponse<JVal> = self.client
            .post(self.api_url("getFile"))
            .json(&params).send().await?.json().await?;
        if !resp.ok {
            return Err(GravError::Bot(resp.description.unwrap_or_else(|| "getFile failed".into())));
        }
        let result = resp.result.ok_or_else(|| GravError::Bot("getFile: empty result".into()))?;
        let file_path = result.get("file_path")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let file_size = result.get("file_size")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        Ok((file_path, file_size))
    }

    /// Download file bytes by file_path (obtained from get_file).
    pub async fn download_file_bytes(&self, file_path: &str) -> GravResult<Vec<u8>> {
        let url = format!("https://api.telegram.org/file/bot{}/{}", self.token, file_path);
        let bytes = self.client.get(&url).send().await?.bytes().await?;
        Ok(bytes.to_vec())
    }

    /// Register a webhook URL with Telegram.
    pub async fn set_webhook(&self, url: &str, secret: Option<&str>) -> GravResult<()> {
        let mut params = serde_json::json!({ "url": url });
        if let Some(s) = secret {
            params["secret_token"] = serde_json::Value::String(s.to_string());
        }
        let resp: ApiResponse<JVal> = self.client
            .post(self.api_url("setWebhook"))
            .json(&params).send().await?.json().await?;
        if !resp.ok {
            return Err(GravError::Bot(resp.description.unwrap_or_else(|| "setWebhook failed".into())));
        }
        Ok(())
    }

    /// Delete the current webhook (switch back to long-polling).
    pub async fn delete_webhook(&self) -> GravResult<()> {
        let _ = self.client.post(self.api_url("deleteWebhook")).send().await;
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Bot runner — long-polling loop
// ─────────────────────────────────────────────────────────────────────────────

pub struct BotRunner {
    pub interpreter: Arc<Interpreter>,
    pub tg:          TelegramClient,
    pub program:     Arc<Program>,
    pub admin_ids:   Vec<i64>,
}

impl BotRunner {
    pub fn new(
        token:     String,
        program:   Arc<Program>,
        admin_ids: Vec<i64>,
    ) -> Self {
        let tg          = TelegramClient::new(token.clone());
        let interpreter = Arc::new(Interpreter::new(token));
        Self { interpreter, tg, program, admin_ids }
    }

    pub async fn run(&self) -> GravResult<()> {
        // Load program into interpreter (register fns, flows, state)
        self.interpreter.load(&self.program).await?;

        // Set admin IDs
        {
            let mut st = self.interpreter.shared.lock().await;
            st.admin_ids = self.admin_ids.clone();
        }

        // Announce startup
        let me = self.tg.get_me().await?;
        println!("[gravitix] Bot @{} started.",
            me.username.unwrap_or_else(|| me.first_name));

        let local = tokio::task::LocalSet::new();
        local.run_until(async {
            // Start schedulers (must be inside LocalSet for spawn_local)
            self.start_schedulers().await;

            // Long-polling loop
            let mut offset = 0i64;
            loop {
                match self.tg.get_updates(offset, 30).await {
                    Err(e) => {
                        eprintln!("[gravitix] polling error: {e}");
                        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                    }
                    Ok(updates) => {
                        for upd in updates {
                            offset = upd.update_id + 1;
                            if let Some(msg) = upd.message {
                                self.handle_message(msg).await;
                            } else if let Some(cb) = upd.callback_query {
                                self.handle_callback_query(cb).await;
                            }
                        }
                    }
                }
            }
        }).await
    }

    async fn handle_message(&self, msg: Message) {
        let chat_id = msg.chat.id;

        // Show typing indicator (fire-and-forget)
        let tg2 = self.tg.clone();
        tokio::task::spawn_local(async move {
            let _ = tg2.send_chat_action(chat_id, "typing").await;
        });

        let user = msg.from.clone().unwrap_or_else(|| User {
            id: 0, first_name: "Unknown".into(),
            last_name: None, username: None, is_bot: false,
        });

        let is_admin = self.admin_ids.contains(&user.id);

        // Extract the best file_id from media attachments
        let media_file_id = msg.photo.as_ref()
            .and_then(|arr| arr.last())
            .and_then(|p| p.get("file_id"))
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .or_else(|| Self::media_file_id_from(&msg.document))
            .or_else(|| Self::media_file_id_from(&msg.video))
            .or_else(|| Self::media_file_id_from(&msg.voice))
            .or_else(|| Self::media_file_id_from(&msg.audio))
            .or_else(|| Self::media_file_id_from(&msg.animation))
            .or_else(|| Self::media_file_id_from(&msg.sticker));

        let ctx = BotCtx {
            chat_id,
            user_id:       user.id,
            username:      user.username.clone(),
            first_name:    user.first_name.clone(),
            last_name:     user.last_name.clone(),
            msg_text:      msg.text.clone(),
            msg_id:        msg.message_id,
            is_admin,
            callback_data: None,
            callback_id:   None,
            chat_type:     msg.chat.type_.clone(),
            media_file_id,
        };

        let update_type = if msg.photo.is_some()          { "photo" }
                          else if msg.video.is_some()      { "video" }
                          else if msg.voice.is_some()      { "voice" }
                          else if msg.audio.is_some()      { "audio" }
                          else if msg.animation.is_some()  { "animation" }
                          else if msg.document.is_some()   { "document" }
                          else if msg.sticker.is_some()    { "sticker" }
                          else { "msg" };

        let interp   = Arc::clone(&self.interpreter);
        let program  = Arc::clone(&self.program);
        let tg       = self.tg.clone();

        tokio::task::spawn_local(async move {
            match interp.dispatch(&program, ctx, update_type).await {
                Err(e) => eprintln!("[gravitix] handler error: {e}"),
                Ok(outputs) => dispatch_outputs(outputs, chat_id, &tg).await,
            }
        });
    }

    /// Extract file_id from an optional media JVal object.
    fn media_file_id_from(v: &Option<JVal>) -> Option<String> {
        v.as_ref()
            .and_then(|j| j.get("file_id"))
            .and_then(|v| v.as_str())
            .map(str::to_string)
    }

    async fn handle_callback_query(&self, cb: CallbackQuery) {
        let chat_id = cb.message.as_ref().map(|m| m.chat.id).unwrap_or(0);
        let msg_id  = cb.message.as_ref().map(|m| m.message_id).unwrap_or(0);
        let is_admin = self.admin_ids.contains(&cb.from.id);

        let chat_type = cb.message.as_ref().map(|m| m.chat.type_.clone()).unwrap_or_default();
        let ctx = BotCtx {
            chat_id,
            user_id:       cb.from.id,
            username:      cb.from.username.clone(),
            first_name:    cb.from.first_name.clone(),
            last_name:     cb.from.last_name.clone(),
            msg_text:      cb.data.clone(),
            msg_id,
            is_admin,
            callback_data: cb.data.clone(),
            callback_id:   Some(cb.id.clone()),
            chat_type,
            media_file_id: None,
        };

        let interp  = Arc::clone(&self.interpreter);
        let program = Arc::clone(&self.program);
        let tg      = self.tg.clone();
        let cb_id   = cb.id.clone();

        tokio::task::spawn_local(async move {
            match interp.dispatch(&program, ctx, "callback").await {
                Err(e) => eprintln!("[gravitix] callback handler error: {e}"),
                Ok(outputs) => {
                    // Auto-answer callback if not answered by script
                    let answered = outputs.iter().any(|o| matches!(o, BotOutput::AnswerCallback { .. }));
                    dispatch_outputs(outputs, chat_id, &tg).await;
                    if !answered {
                        let _ = tg.answer_callback(&cb_id, None).await;
                    }
                }
            }
        });
    }

    /// Start every/at schedulers as background tasks
    pub async fn start_schedulers(&self) {
        let every_defs = {
            let st = self.interpreter.shared.lock().await;
            st.every_defs.clone()
        };
        let at_defs = {
            let st = self.interpreter.shared.lock().await;
            st.at_defs.clone()
        };

        for ev in every_defs {
            let interp  = Arc::clone(&self.interpreter);
            let program = Arc::clone(&self.program);
            let tg      = self.tg.clone();
            let secs = match ev.unit {
                crate::ast::TimeUnit::Sec  => ev.amount,
                crate::ast::TimeUnit::Min  => ev.amount * 60,
                crate::ast::TimeUnit::Hour => ev.amount * 3600,
                crate::ast::TimeUnit::Day  => ev.amount * 86400,
            };

            tokio::task::spawn_local(async move {
                let mut interval = tokio::time::interval(
                    tokio::time::Duration::from_secs(secs)
                );
                interval.tick().await; // skip immediate first tick
                loop {
                    interval.tick().await;
                    // Run the every-block (no ctx — uses state and emit_to only)
                    let mut env = crate::interpreter::Env::new();
                    let mut outputs = Vec::new();
                    let _ = Box::pin(interp.eval_block_public(&ev.body, &mut env, None, &mut outputs)).await;
                    let known_chats = interp.shared.lock().await.known_chats.clone();
                    for out in outputs {
                        dispatch_scheduler_output(out, &known_chats, &tg).await;
                    }
                }
            });
        }

        for at in at_defs {
            let interp  = Arc::clone(&self.interpreter);
            let tg      = self.tg.clone();
            let time_str = at.time.clone();

            tokio::task::spawn_local(async move {
                loop {
                    let secs = secs_until(&time_str);
                    tokio::time::sleep(tokio::time::Duration::from_secs(secs)).await;

                    let mut env = crate::interpreter::Env::new();
                    let mut outputs = Vec::new();
                    let _ = Box::pin(interp.eval_block_public(&at.body, &mut env, None, &mut outputs)).await;
                    let known_chats = interp.shared.lock().await.known_chats.clone();
                    for out in outputs {
                        dispatch_scheduler_output(out, &known_chats, &tg).await;
                    }
                    // Sleep a bit so we don't fire twice in the same minute
                    tokio::time::sleep(tokio::time::Duration::from_secs(70)).await;
                }
            });
        }
    }
}

// ── output dispatch helpers ───────────────────────────────────────────────────

/// Process a Vec<BotOutput> for a message handler (chat_id = originating chat).
async fn dispatch_outputs(outputs: Vec<BotOutput>, chat_id: i64, tg: &TelegramClient) {
    for out in outputs {
        match out {
            BotOutput::Broadcast(ref text) => {
                if let Err(e) = tg.send_message(chat_id, text).await {
                    eprintln!("[gravitix] send error: {e}");
                }
            }
            BotOutput::Direct { chat_id: id, ref text } => {
                if let Err(e) = tg.send_message(id, text).await {
                    eprintln!("[gravitix] send error: {e}");
                }
            }
            BotOutput::Keyboard { chat_id: id, ref text, ref buttons } => {
                if let Err(e) = tg.send_with_keyboard(id, text, buttons).await {
                    eprintln!("[gravitix] keyboard send error: {e}");
                }
            }
            BotOutput::EditMessage { chat_id: id, msg_id, ref text } => {
                if let Err(e) = tg.edit_message(id, msg_id, text).await {
                    eprintln!("[gravitix] editMessage error: {e}");
                }
            }
            BotOutput::AnswerCallback { ref callback_id, ref text } => {
                if let Err(e) = tg.answer_callback(callback_id, text.as_deref()).await {
                    eprintln!("[gravitix] answerCallback error: {e}");
                }
            }
            BotOutput::SendMedia { chat_id: id, ref kind, ref source, ref caption } => {
                if let Err(e) = tg.send_media(id, kind, source, caption.as_deref()).await {
                    eprintln!("[gravitix] sendMedia error: {e}");
                }
            }
            BotOutput::ForwardMsg { from_chat, to_chat, msg_id } => {
                if let Err(e) = tg.forward_message(to_chat, from_chat, msg_id).await {
                    eprintln!("[gravitix] forwardMessage error: {e}");
                }
            }
        }
    }
}

/// Process a BotOutput for scheduler tasks — Broadcast goes to all known chats.
async fn dispatch_scheduler_output(out: BotOutput, known_chats: &[i64], tg: &TelegramClient) {
    match out {
        BotOutput::Broadcast(ref text) => {
            for &cid in known_chats { let _ = tg.send_message(cid, text).await; }
        }
        BotOutput::Direct { chat_id: id, ref text } => { let _ = tg.send_message(id, text).await; }
        BotOutput::Keyboard { chat_id: id, ref text, ref buttons } => {
            let _ = tg.send_with_keyboard(id, text, buttons).await;
        }
        BotOutput::EditMessage { chat_id: id, msg_id, ref text } => {
            let _ = tg.edit_message(id, msg_id, text).await;
        }
        BotOutput::AnswerCallback { ref callback_id, ref text } => {
            let _ = tg.answer_callback(callback_id, text.as_deref()).await;
        }
        BotOutput::SendMedia { chat_id: id, ref kind, ref source, ref caption } => {
            let _ = tg.send_media(id, kind, source, caption.as_deref()).await;
        }
        BotOutput::ForwardMsg { from_chat, to_chat, msg_id } => {
            let _ = tg.forward_message(to_chat, from_chat, msg_id).await;
        }
    }
}

// ── time helpers ──────────────────────────────────────────────────────────────

/// Returns seconds until the next HH:MM
fn secs_until(time_str: &str) -> u64 {
    let parts: Vec<&str> = time_str.split(':').collect();
    let target_h: u64 = parts.first().and_then(|s| s.parse().ok()).unwrap_or(9);
    let target_m: u64 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);

    use std::time::{SystemTime, UNIX_EPOCH};
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let day_secs = now_secs % 86400;
    let target_secs = target_h * 3600 + target_m * 60;
    if target_secs > day_secs {
        target_secs - day_secs
    } else {
        86400 - day_secs + target_secs
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Webhook server
// ─────────────────────────────────────────────────────────────────────────────

impl BotRunner {
    /// Run the bot in webhook mode.
    /// `public_url` — full HTTPS URL Telegram will POST updates to (e.g. https://my.host/webhook)
    /// `port`       — local TCP port to listen on (put nginx/ngrok in front for TLS)
    /// `secret`     — optional X-Telegram-Bot-Api-Secret-Token for request verification
    pub async fn run_webhook(
        &self,
        public_url: &str,
        port:       u16,
        secret:     Option<String>,
    ) -> GravResult<()> {
        self.interpreter.load(&self.program).await?;
        {
            let mut st = self.interpreter.shared.lock().await;
            st.admin_ids = self.admin_ids.clone();
        }

        // Register webhook with Telegram
        self.tg.set_webhook(public_url, secret.as_deref()).await?;
        let me = self.tg.get_me().await?;
        println!("[gravitix] Bot @{} webhook listening on port {port}",
            me.username.unwrap_or_else(|| me.first_name));

        let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
            .await
            .map_err(|e| GravError::Bot(format!("webhook bind port {port}: {e}")))?;

        loop {
            match listener.accept().await {
                Err(e) => eprintln!("[gravitix] webhook accept error: {e}"),
                Ok((stream, _addr)) => {
                    let runner = Arc::new(BotRunner {
                        interpreter: Arc::clone(&self.interpreter),
                        tg:          self.tg.clone(),
                        program:     Arc::clone(&self.program),
                        admin_ids:   self.admin_ids.clone(),
                    });
                    let secret2 = secret.clone();
                    tokio::task::spawn_local(async move {
                        handle_webhook_connection(stream, runner, secret2).await;
                    });
                }
            }
        }
    }
}

async fn handle_webhook_connection(
    mut stream: tokio::net::TcpStream,
    runner:     Arc<BotRunner>,
    secret:     Option<String>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Read until we have the full headers (double CRLF)
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        match stream.read(&mut tmp).await {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") { break; }
                if buf.len() > 16_384 { return; } // too large
            }
        }
    }

    let header_end = match buf.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(p) => p + 4,
        None    => return,
    };
    let header_str = match std::str::from_utf8(&buf[..header_end]) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Verify secret token if required
    if let Some(ref expected) = secret {
        let header_secret = header_str.lines()
            .find(|l| l.to_lowercase().starts_with("x-telegram-bot-api-secret-token:"))
            .and_then(|l| l.splitn(2, ':').nth(1))
            .map(str::trim)
            .unwrap_or("");
        if header_secret != expected {
            let _ = stream.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n").await;
            return;
        }
    }

    // Parse Content-Length
    let content_length: usize = header_str.lines()
        .find(|l| l.to_lowercase().starts_with("content-length:"))
        .and_then(|l| l.splitn(2, ':').nth(1))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);

    // Read body (may already be partly in buf)
    let already = buf.len() - header_end;
    let mut body = buf[header_end..].to_vec();
    if already < content_length {
        let need = content_length - already;
        let mut rest = vec![0u8; need];
        if stream.read_exact(&mut rest).await.is_err() { return; }
        body.extend_from_slice(&rest);
    }

    // Respond immediately
    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;

    // Parse and dispatch
    let upd: Update = match serde_json::from_slice(&body) {
        Ok(u) => u,
        Err(e) => { eprintln!("[gravitix] webhook parse error: {e}"); return; }
    };

    if let Some(msg) = upd.message {
        runner.handle_message(msg).await;
    } else if let Some(cb) = upd.callback_query {
        runner.handle_callback_query(cb).await;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Expose exec_block as public for schedulers (avoids private-in-public issues)
// ─────────────────────────────────────────────────────────────────────────────

use crate::ast::Stmt;
use std::rc::Rc;
use std::cell::RefCell;

impl Interpreter {
    pub async fn eval_block_public(
        &self,
        stmts:   &[Stmt],
        env:     &mut crate::interpreter::Env,
        ctx:     Option<Rc<RefCell<BotCtx>>>,
        outputs: &mut Vec<BotOutput>,
    ) -> GravResult<crate::value::Value> {
        self.exec_block_pub(stmts, env, ctx, outputs).await
            .map_err(GravError::Runtime)
    }
}
