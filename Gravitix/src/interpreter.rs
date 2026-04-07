use std::collections::HashMap;
use std::rc::Rc;
use std::cell::RefCell;
use std::sync::Arc;
use tokio::sync::Mutex;

use regex::Regex;

use crate::ast::*;
use crate::error::{GravError, GravResult};
use crate::lexer::StrPart;
use crate::value::{BotCtx, BotOutput, Value};
use crate::{runtime_err, type_err};

// ─────────────────────────────────────────────────────────────────────────────
// Environment: a simple Vec<Frame> stack for O(1) push/pop
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct Frame {
    vars: HashMap<String, Value>,
}

impl Frame {
    fn new() -> Self { Self { vars: HashMap::new() } }
}

#[derive(Clone)]
pub struct Env {
    frames: Vec<Frame>,
}

impl Env {
    pub fn new() -> Self { Self { frames: vec![Frame::new()] } }

    pub fn push(&mut self) { self.frames.push(Frame::new()); }

    pub fn pop(&mut self) { if self.frames.len() > 1 { self.frames.pop(); } }

    pub fn get(&self, name: &str) -> Option<Value> {
        for frame in self.frames.iter().rev() {
            if let Some(v) = frame.vars.get(name) { return Some(v.clone()); }
        }
        None
    }

    pub fn set(&mut self, name: &str, val: Value) {
        // update existing binding first (any frame)
        for frame in self.frames.iter_mut().rev() {
            if frame.vars.contains_key(name) {
                frame.vars.insert(name.to_string(), val);
                return;
            }
        }
        // otherwise declare in current frame
        self.frames.last_mut().unwrap().vars.insert(name.to_string(), val);
    }

    pub fn define(&mut self, name: &str, val: Value) {
        self.frames.last_mut().unwrap().vars.insert(name.to_string(), val);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared interpreter state (program-level)
// ─────────────────────────────────────────────────────────────────────────────

pub struct SharedState {
    /// Global persistent state  (the `state { … }` block)
    pub bot_state:     HashMap<String, Value>,
    /// Compiled regex cache (pattern+flags -> Regex) — pre-compiled once
    pub regex_cache:   HashMap<String, Regex>,
    /// `fn` definitions
    pub functions:     HashMap<String, Rc<FnDef>>,
    /// `flow` definitions
    pub flows:         HashMap<String, FlowDef>,
    /// `every` / `at` defs stored for scheduler
    pub every_defs:    Vec<EveryDef>,
    pub at_defs:       Vec<AtDef>,
    /// Pending wait channels: (chat_id, user_id) -> Sender<String> — isolated per user
    pub wait_map:      HashMap<(i64, i64), tokio::sync::oneshot::Sender<String>>,
    /// Admin user IDs (set at startup from token config)
    pub admin_ids:     Vec<i64>,
    /// All chat IDs the bot has ever seen (for broadcast)
    pub known_chats:   Vec<i64>,
    /// Telegram token (for emit_to)
    pub bot_token:     String,
    /// Path for persisting bot_state to JSON (None = no persistence)
    pub state_file:    Option<String>,
    /// `struct` definitions: name -> field list (name, type)
    pub struct_defs:   HashMap<String, Vec<(String, crate::ast::TypeExpr)>>,
    /// Call stack for error reporting: (fn_name, defined_at_line)
    pub call_stack:    Vec<(String, u32)>,
}

impl SharedState {
    pub fn new(token: String) -> Self {
        Self {
            bot_state:   HashMap::new(),
            regex_cache: HashMap::new(),
            functions:   HashMap::new(),
            flows:       HashMap::new(),
            every_defs:  Vec::new(),
            at_defs:     Vec::new(),
            wait_map:    HashMap::new(),
            admin_ids:   Vec::new(),
            known_chats: Vec::new(),
            bot_token:   token,
            state_file:  Some("bot_state.json".to_string()),
            struct_defs: HashMap::new(),
            call_stack:  Vec::new(),
        }
    }

    pub fn get_or_compile_regex(&mut self, pattern: &str, flags: &str) -> GravResult<Regex> {
        let key = format!("{pattern}/{flags}");
        if let Some(r) = self.regex_cache.get(&key) { return Ok(r.clone()); }
        let mut prefix = String::new();
        if flags.contains('i') { prefix.push_str("(?i)"); }
        if flags.contains('m') { prefix.push_str("(?m)"); }
        if flags.contains('s') { prefix.push_str("(?s)"); }
        if flags.contains('x') { prefix.push_str("(?x)"); }
        let re = Regex::new(&format!("{prefix}{pattern}"))
            .map_err(|e| runtime_err!("invalid regex /{pattern}/{flags}: {e}"))?;
        self.regex_cache.insert(key, re.clone());
        Ok(re)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Interpreter
// ─────────────────────────────────────────────────────────────────────────────

pub struct Interpreter {
    pub shared: Arc<Mutex<SharedState>>,
}

impl Interpreter {
    pub fn new(token: String) -> Self {
        Self { shared: Arc::new(Mutex::new(SharedState::new(token))) }
    }

    /// Load a program: register fns, flows, state fields, schedulers.
    /// Does NOT run handlers yet.
    pub async fn load(&self, prog: &Program) -> GravResult<()> {
        let mut st = self.shared.lock().await;
        for item in &prog.items {
            match item {
                Item::FnDef(fd) => {
                    st.functions.insert(fd.name.clone(), Rc::new(fd.clone()));
                }
                Item::FlowDef(fd) => {
                    st.flows.insert(fd.name.clone(), fd.clone());
                }
                Item::StateDef(sd) => {
                    // Initialize state fields with defaults
                    for field in &sd.fields {
                        if let Some(default_expr) = &field.default {
                            // Evaluate constant default (no ctx needed)
                            let mut env = Env::new();
                            drop(st); // release lock during eval
                            let val = self.eval_expr(default_expr, &mut env, None).await?;
                            st = self.shared.lock().await;
                            st.bot_state.insert(field.name.clone(), val);
                        } else {
                            st.bot_state.insert(field.name.clone(), Value::Null);
                        }
                    }
                }
                Item::Every(e) => { st.every_defs.push(e.clone()); }
                Item::At(a)    => { st.at_defs.push(a.clone()); }
                Item::StructDef(sd) => {
                    st.struct_defs.insert(sd.name.clone(), sd.fields.clone());
                }
                Item::Use(path) => {
                    // Load and parse the included file, then register its items
                    drop(st);
                    match std::fs::read_to_string(path) {
                        Ok(src) => {
                            let mut lexer = crate::lexer::Lexer::new(&src);
                            let tokens = lexer.tokenize().map_err(|e| crate::error::GravError::Runtime(e.to_string()))?;
                            let parser = crate::parser::Parser::new(tokens);
                            let included = parser.parse().map_err(|e: crate::error::GravError| crate::error::GravError::Runtime(e.to_string()))?;
                            Box::pin(self.load(&included)).await?;
                        }
                        Err(e) => {
                            eprintln!("[use] warning: cannot read '{}': {}", path, e);
                        }
                    }
                    st = self.shared.lock().await;
                }
                Item::Handler(_) | Item::Stmt(_) | Item::TestDef(_) => {} // handled at runtime
            }
        }
        // Auto-load persisted state if the file exists
        if let Some(path) = st.state_file.clone() {
            if let Ok(text) = std::fs::read_to_string(&path) {
                if let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(&text) {
                    for (k, v) in map {
                        st.bot_state.entry(k).or_insert_with(|| crate::stdlib::json_to_value(v));
                    }
                }
            }
        }
        Ok(())
    }

    // ── test runner ──────────────────────────────────────────────────────────

    /// Run all `test "name" { body }` blocks and return (passed, failed) counts
    /// with per-test results: Vec<(name, Ok(()) | Err(message))>
    pub async fn run_tests(&self, prog: &Program) -> Vec<(String, Result<(), String>)> {
        let mut results = Vec::new();
        for item in &prog.items {
            let Item::TestDef(test) = item else { continue };
            let mut env = Env::new();
            let mut outputs = Vec::new();
            let outcome = Box::pin(self.exec_block(&test.body, &mut env, None, &mut outputs)).await;
            let result = match outcome {
                Ok(_)                   => Ok(()),
                Err(ExecErr::Err(e))    => Err(e.to_string()),
                Err(ExecErr::Return(_)) => Ok(()),
                Err(ExecErr::Break)     => Err("unexpected break in test".to_string()),
                Err(ExecErr::Continue)  => Err("unexpected continue in test".to_string()),
            };
            results.push((test.name.clone(), result));
        }
        results
    }

    /// Public wrapper around `exec_stmt` for use in the REPL.
    pub async fn exec_stmt_pub(
        &self,
        stmt:    &Stmt,
        env:     &mut Env,
        ctx:     Option<Rc<RefCell<BotCtx>>>,
        outputs: &mut Vec<BotOutput>,
    ) -> GravResult<()> {
        self.exec_stmt(stmt, env, ctx, outputs).await
            .map(|_| ())
            .map_err(|e| match e {
                ExecErr::Err(e)    => e,
                ExecErr::Return(_) => GravError::Runtime("unexpected return outside function".into()),
                ExecErr::Break     => GravError::Runtime("unexpected break".into()),
                ExecErr::Continue  => GravError::Runtime("unexpected continue".into()),
            })
    }

    // ── dispatch an incoming Telegram message ─────────────────────────────────

    pub async fn dispatch(
        &self,
        prog:    &Program,
        ctx:     BotCtx,
        update_type: &str,   // "msg", "photo", "video", "voice", "document", "sticker"
    ) -> GravResult<Vec<BotOutput>> {
        let chat_id = ctx.chat_id;
        let msg_text = ctx.msg_text.clone().unwrap_or_default();

        // Check if a flow is waiting for this chat's reply
        let maybe_sender = {
            let mut st = self.shared.lock().await;
            st.known_chats.retain(|&c| c != chat_id);
            st.known_chats.push(chat_id);
            // Cap to 10 000 entries — evict oldest on overflow
            const MAX_KNOWN_CHATS: usize = 10_000;
            let len = st.known_chats.len();
            if len > MAX_KNOWN_CHATS {
                st.known_chats.drain(0..len - MAX_KNOWN_CHATS);
            }
            st.wait_map.remove(&(chat_id, ctx.user_id))
        };
        if let Some(sender) = maybe_sender {
            let _ = sender.send(msg_text.clone());
            return Ok(vec![]);
        }

        let ctx_rc = Rc::new(RefCell::new(ctx));
        let mut outputs: Vec<BotOutput> = Vec::new();

        for item in &prog.items {
            let Item::Handler(handler) = item else { continue };
            let matches = match &handler.trigger {
                Trigger::Command(cmd) => update_type == "msg" && (msg_text.trim() == format!("/{cmd}") || msg_text.trim().starts_with(&format!("/{cmd} "))),
                Trigger::AnyMsg      => update_type == "msg",
                Trigger::Photo       => update_type == "photo",
                Trigger::Video       => update_type == "video",
                Trigger::Voice       => update_type == "voice",
                Trigger::Document    => update_type == "document",
                Trigger::Sticker     => update_type == "sticker",
                Trigger::Any         => true,
                Trigger::CallbackQuery(pattern) => {
                    if update_type != "callback" { false } else {
                        match pattern {
                            None    => true,
                            Some(p) => ctx_rc.borrow().callback_data.as_deref()
                                           .unwrap_or("").starts_with(p.as_str()),
                        }
                    }
                }
            };
            if !matches { continue; }

            // Evaluate guard if present
            if let Some(guard_expr) = &handler.guard {
                let mut env = Env::new();
                env.define("ctx", Value::Ctx(ctx_rc.clone()));
                let guard_val = self.eval_expr(guard_expr, &mut env, Some(ctx_rc.clone())).await?;
                if !guard_val.is_truthy() { continue; }
            }

            // Run handler body
            let mut env = Env::new();
            env.define("ctx", Value::Ctx(ctx_rc.clone()));
            match self.exec_block(&handler.body, &mut env, Some(ctx_rc.clone()), &mut outputs).await {
                Ok(_) => {}
                Err(ExecErr::Err(e))    => return Err(e),
                Err(ExecErr::Return(_)) => {}
                Err(ExecErr::Break | ExecErr::Continue) => {}
            }
            break; // first matching handler wins
        }

        Ok(outputs)
    }

    // ── run a flow by name ────────────────────────────────────────────────────

    pub async fn run_flow(
        &self,
        name:    &str,
        ctx_rc:  Rc<RefCell<BotCtx>>,
        outputs: &mut Vec<BotOutput>,
    ) -> GravResult<()> {
        let flow = {
            let st = self.shared.lock().await;
            st.flows.get(name).cloned()
                .ok_or_else(|| runtime_err!("undefined flow '{name}'"))?
        };
        let mut env = Env::new();
        env.define("ctx", Value::Ctx(ctx_rc.clone()));
        match self.exec_block(&flow.body, &mut env, Some(ctx_rc), outputs).await {
            Ok(_) | Err(ExecErr::Return(_)) => Ok(()),
            Err(ExecErr::Err(e)) => Err(e),
            Err(ExecErr::Break | ExecErr::Continue) => Ok(()),
        }
    }

    // ── execute a block of statements ─────────────────────────────────────────

    async fn exec_block(
        &self,
        stmts:   &[Stmt],
        env:     &mut Env,
        ctx:     Option<Rc<RefCell<BotCtx>>>,
        outputs: &mut Vec<BotOutput>,
    ) -> Result<Value, ExecErr> {
        env.push();
        let mut last = Value::Null;
        for stmt in stmts {
            last = Box::pin(self.exec_stmt(stmt, env, ctx.clone(), outputs)).await?;
        }
        env.pop();
        Ok(last)
    }

    // ── execute a statement ───────────────────────────────────────────────────

    async fn exec_stmt(
        &self,
        stmt:    &Stmt,
        env:     &mut Env,
        ctx:     Option<Rc<RefCell<BotCtx>>>,
        outputs: &mut Vec<BotOutput>,
    ) -> Result<Value, ExecErr> {
        match stmt {
            Stmt::Let { name, ty, value } => {
                let v = self.eval_expr(value, env, ctx.clone()).await?;
                if let Some(t) = ty {
                    typecheck(t, &v).map_err(|e| ExecErr::Err(e))?;
                }
                env.define(name, v);
                Ok(Value::Null)
            }

            Stmt::Assign { target, value } => {
                let v = self.eval_expr(value, env, ctx.clone()).await?;
                self.assign_target(target, v, env, ctx.clone()).await?;
                Ok(Value::Null)
            }

            Stmt::CompoundAssign { target, op, value } => {
                let current = self.eval_expr(target, env, ctx.clone()).await?;
                let rhs     = self.eval_expr(value, env, ctx.clone()).await?;
                let result  = apply_binop(op.clone(), current, rhs).map_err(ExecErr::Err)?;
                self.assign_target(target, result, env, ctx.clone()).await?;
                Ok(Value::Null)
            }

            Stmt::Emit(expr) => {
                let v = self.eval_expr(expr, env, ctx.clone()).await?;
                outputs.push(BotOutput::Broadcast(v.to_string()));
                Ok(Value::Null)
            }

            Stmt::EmitTo { target, msg } => {
                let target_val = self.eval_expr(target, env, ctx.clone()).await?;
                let v          = self.eval_expr(msg, env, ctx.clone()).await?;
                let chat_id    = target_val.as_int()
                    .ok_or_else(|| ExecErr::Err(runtime_err!("emit_to: target must evaluate to an integer chat_id")))?;
                outputs.push(BotOutput::Direct { chat_id, text: v.to_string() });
                Ok(Value::Null)
            }

            Stmt::Return(expr) => {
                let v = match expr {
                    Some(e) => self.eval_expr(e, env, ctx.clone()).await?,
                    None    => Value::Null,
                };
                Err(ExecErr::Return(v))
            }

            Stmt::Break    => Err(ExecErr::Break),
            Stmt::Continue => Err(ExecErr::Continue),

            Stmt::If { cond, then, elif, else_ } => {
                let c = self.eval_expr(cond, env, ctx.clone()).await?;
                if c.is_truthy() {
                    Box::pin(self.exec_block(then, env, ctx.clone(), outputs)).await?;
                } else {
                    let mut matched = false;
                    for (ec, eb) in elif {
                        let ev = self.eval_expr(ec, env, ctx.clone()).await?;
                        if ev.is_truthy() {
                            Box::pin(self.exec_block(eb, env, ctx.clone(), outputs)).await?;
                            matched = true;
                            break;
                        }
                    }
                    if !matched {
                        if let Some(eb) = else_ {
                            Box::pin(self.exec_block(eb, env, ctx.clone(), outputs)).await?;
                        }
                    }
                }
                Ok(Value::Null)
            }

            Stmt::While { cond, body } => {
                loop {
                    let c = self.eval_expr(cond, env, ctx.clone()).await?;
                    if !c.is_truthy() { break; }
                    match Box::pin(self.exec_block(body, env, ctx.clone(), outputs)).await {
                        Ok(_) => {}
                        Err(ExecErr::Break) => break,
                        Err(ExecErr::Continue) => continue,
                        Err(e) => return Err(e),
                    }
                }
                Ok(Value::Null)
            }

            Stmt::For { var, iter, body } => {
                let iterable = self.eval_expr(iter, env, ctx.clone()).await?;
                let items: Vec<Value> = match &iterable {
                    Value::List(l) => l.borrow().clone(),
                    Value::Map(m)  => m.borrow().keys().map(|k| Value::make_str(k)).collect(),
                    _ => return Err(ExecErr::Err(type_err!("iterable", iterable.type_name()))),
                };
                for item in items {
                    env.push();
                    env.define(var, item);
                    match Box::pin(self.exec_block(body, env, ctx.clone(), outputs)).await {
                        Ok(_) => {}
                        Err(ExecErr::Break) => { env.pop(); break; }
                        Err(ExecErr::Continue) => { env.pop(); continue; }
                        Err(e) => { env.pop(); return Err(e); }
                    }
                    env.pop();
                }
                Ok(Value::Null)
            }

            Stmt::Match { subject, arms } => {
                let val = self.eval_expr(subject, env, ctx.clone()).await?;
                for arm in arms {
                    let captures = self.match_pattern(&arm.pattern, &val).await
                        .map_err(ExecErr::Err)?;
                    if let Some(caps) = captures {
                        // Expose $0 (full match), $1, $2 … (groups)
                        for (i, cap) in caps.iter().enumerate() {
                            env.define(&format!("${i}"), Value::make_str(cap.clone()));
                        }
                        // Bind name for Bind pattern
                        if let Pattern::Bind { name, .. } = &arm.pattern {
                            env.define(name, val.clone());
                        }
                        Box::pin(self.exec_block(&arm.body, env, ctx.clone(), outputs)).await?;
                        break;
                    }
                }
                Ok(Value::Null)
            }

            Stmt::RunFlow(name) => {
                let ctx_rc = ctx.ok_or_else(|| ExecErr::Err(runtime_err!("run flow requires ctx")))?;
                self.run_flow(name, ctx_rc, outputs).await.map_err(ExecErr::Err)?;
                Ok(Value::Null)
            }

            Stmt::TryCatch { try_body, err_name, catch_body } => {
                match Box::pin(self.exec_block(try_body, env, ctx.clone(), outputs)).await {
                    Ok(v) => Ok(v),
                    Err(ExecErr::Err(e)) => {
                        env.define(err_name, Value::make_str(format!("{e:?}")));
                        Box::pin(self.exec_block(catch_body, env, ctx.clone(), outputs)).await
                    }
                    Err(e) => Err(e), // re-raise break/continue/return
                }
            }

            Stmt::SendKeyboard { text, buttons } => {
                let text_val    = self.eval_expr(text, env, ctx.clone()).await.map_err(ExecErr::Err)?;
                let buttons_val = self.eval_expr(buttons, env, ctx.clone()).await.map_err(ExecErr::Err)?;
                let chat_id     = ctx.as_ref().map(|c| c.borrow().chat_id).unwrap_or(0);
                let btns        = parse_keyboard_buttons(&buttons_val).map_err(ExecErr::Err)?;
                outputs.push(BotOutput::Keyboard { chat_id, text: text_val.to_string(), buttons: btns });
                Ok(Value::Null)
            }

            Stmt::EditMsg { msg_id, text } => {
                let id_val   = self.eval_expr(msg_id, env, ctx.clone()).await.map_err(ExecErr::Err)?;
                let text_val = self.eval_expr(text, env, ctx.clone()).await.map_err(ExecErr::Err)?;
                let chat_id  = ctx.as_ref().map(|c| c.borrow().chat_id).unwrap_or(0);
                let mid      = id_val.as_int().ok_or_else(|| ExecErr::Err(runtime_err!("edit: msg_id must be integer")))?;
                outputs.push(BotOutput::EditMessage { chat_id, msg_id: mid, text: text_val.to_string() });
                Ok(Value::Null)
            }

            Stmt::AnswerCallback(text_expr) => {
                let cb_id = ctx.as_ref()
                    .and_then(|c| c.borrow().callback_id.clone())
                    .unwrap_or_default();
                let text = if let Some(e) = text_expr {
                    Some(self.eval_expr(e, env, ctx.clone()).await.map_err(ExecErr::Err)?.to_string())
                } else { None };
                outputs.push(BotOutput::AnswerCallback { callback_id: cb_id, text });
                Ok(Value::Null)
            }

            Stmt::Expr(expr) => {
                self.eval_expr(expr, env, ctx.clone()).await.map_err(ExecErr::Err)
            }
        }
    }

    // ── keyboard buttons helper ───────────────────────────────────────────────
    // Converts Value::List<Value::List<[label, data]>> to Vec<Vec<(String,String)>>
}

/// #7 — Check that a runtime value matches a declared type annotation.
fn typecheck(ty: &TypeExpr, val: &Value) -> GravResult<()> {
    let ok = match ty {
        TypeExpr::Int     => matches!(val, Value::Int(_)),
        TypeExpr::Float   => matches!(val, Value::Int(_) | Value::Float(_)),
        TypeExpr::Bool    => matches!(val, Value::Bool(_)),
        TypeExpr::Str     => matches!(val, Value::Str(_)),
        TypeExpr::Void    => true,
        TypeExpr::Any     => true,
        TypeExpr::Named(_)=> true, // struct type — checked by __type__ at user level
        TypeExpr::List(_) => matches!(val, Value::List(_)),
        TypeExpr::Map(_, _) => matches!(val, Value::Map(_)),
        TypeExpr::Optional(inner) => {
            matches!(val, Value::Null) || typecheck(inner, val).is_ok()
        }
    };
    if ok { Ok(()) } else {
        Err(runtime_err!("type error: expected {ty:?}, got {}", val.type_name()))
    }
}

fn parse_keyboard_buttons(val: &Value) -> GravResult<Vec<Vec<(String, String)>>> {
    let rows = match val {
        Value::List(l) => l.borrow().clone(),
        _ => return Err(runtime_err!("keyboard: buttons must be a list of rows")),
    };
    let mut result = Vec::with_capacity(rows.len());
    for row in rows {
        let cols = match &row {
            Value::List(l) => l.borrow().clone(),
            _ => return Err(runtime_err!("keyboard: each row must be a list of buttons")),
        };
        let mut row_btns = Vec::with_capacity(cols.len());
        for btn in cols {
            match &btn {
                Value::List(pair) => {
                    let p = pair.borrow();
                    let label = p.first().map(|v| v.to_string()).unwrap_or_default();
                    let data  = p.get(1).map(|v| v.to_string()).unwrap_or_default();
                    row_btns.push((label, data));
                }
                _ => return Err(runtime_err!("keyboard: each button must be [label, data]")),
            }
        }
        result.push(row_btns);
    }
    Ok(result)
}

impl Interpreter {
    // ── evaluate an expression ────────────────────────────────────────────────

    pub async fn eval_expr(
        &self,
        expr: &Expr,
        env:  &mut Env,
        ctx:  Option<Rc<RefCell<BotCtx>>>,
    ) -> GravResult<Value> {
        match expr {
            Expr::Int(n)   => Ok(Value::Int(*n)),
            Expr::Float(f) => Ok(Value::Float(*f)),
            Expr::Bool(b)  => Ok(Value::Bool(*b)),
            Expr::Null     => Ok(Value::Null),

            Expr::Str(parts) => {
                let mut out = String::new();
                for part in parts {
                    match part {
                        StrPart::Lit(s)  => out.push_str(s),
                        StrPart::Hole(src) => {
                            // Re-lex and parse the hole expression
                            let v = Box::pin(self.eval_hole(src, env, ctx.clone())).await?;
                            out.push_str(&v.to_string());
                        }
                    }
                }
                Ok(Value::make_str(out))
            }

            Expr::Var(name) => {
                env.get(name).ok_or_else(|| GravError::UndefinedVar(name.clone()))
            }

            Expr::Ctx => {
                let c = ctx.ok_or_else(|| runtime_err!("'ctx' not available here"))?;
                Ok(Value::Ctx(c))
            }

            Expr::StateRef => {
                let st = self.shared.lock().await;
                let map: HashMap<String, Value> = st.bot_state.clone();
                Ok(Value::make_map(map))
            }

            Expr::EnvVar(key) => {
                let val = std::env::var(key).unwrap_or_default();
                Ok(Value::make_str(val))
            }

            Expr::Wait => {
                let c = ctx.as_ref().ok_or_else(|| runtime_err!("'wait' needs ctx"))?;
                let (chat_id, user_id) = { let b = c.borrow(); (b.chat_id, b.user_id) };
                let (tx, rx) = tokio::sync::oneshot::channel::<String>();
                {
                    let mut st = self.shared.lock().await;
                    st.wait_map.insert((chat_id, user_id), tx);
                }
                let text = rx.await.map_err(|_| runtime_err!("wait channel closed"))?;
                Ok(Value::make_str(text))
            }

            Expr::Unary { op, expr } => {
                let v = Box::pin(self.eval_expr(expr, env, ctx)).await?;
                match op {
                    UnaryOp::Neg => match v {
                        Value::Int(n)   => Ok(Value::Int(-n)),
                        Value::Float(f) => Ok(Value::Float(-f)),
                        _ => Err(type_err!("number", v.type_name())),
                    },
                    UnaryOp::Not => Ok(Value::Bool(!v.is_truthy())),
                }
            }

            Expr::Binary { op, lhs, rhs } => {
                // Short-circuit for && and ||
                match op {
                    BinOp::And => {
                        let l = Box::pin(self.eval_expr(lhs, env, ctx.clone())).await?;
                        if !l.is_truthy() { return Ok(Value::Bool(false)); }
                        let r = Box::pin(self.eval_expr(rhs, env, ctx)).await?;
                        return Ok(Value::Bool(r.is_truthy()));
                    }
                    BinOp::Or => {
                        let l = Box::pin(self.eval_expr(lhs, env, ctx.clone())).await?;
                        if l.is_truthy() { return Ok(Value::Bool(true)); }
                        let r = Box::pin(self.eval_expr(rhs, env, ctx)).await?;
                        return Ok(Value::Bool(r.is_truthy()));
                    }
                    _ => {}
                }
                let l = Box::pin(self.eval_expr(lhs, env, ctx.clone())).await?;
                let r = Box::pin(self.eval_expr(rhs, env, ctx)).await?;
                apply_binop(op.clone(), l, r)
            }

            Expr::Pipe { lhs, fn_name } => {
                let val = Box::pin(self.eval_expr(lhs, env, ctx.clone())).await?;
                let _call = Expr::Call { name: fn_name.clone(), args: vec![] };
                // Call the function with val as first argument
                self.call_fn(fn_name, vec![val], env, ctx).await
            }

            Expr::Call { name, args } => {
                let mut evaluated_args = Vec::with_capacity(args.len());
                for a in args {
                    evaluated_args.push(Box::pin(self.eval_expr(a, env, ctx.clone())).await?);
                }
                // If name resolves to a local closure, call it directly
                if let Some(Value::Fn(fd)) = env.get(name) {
                    return Box::pin(self.call_fn_def(fd, evaluated_args, env, ctx)).await;
                }
                self.call_fn(name, evaluated_args, env, ctx).await
            }

            Expr::Lambda { params, body } => {
                Ok(Value::Fn(Rc::new(FnDef {
                    name:   "λ".to_string(),
                    params: params.clone(),
                    ret:    None,
                    body:   body.clone(),
                    line:   0,
                })))
            }

            Expr::StructLit { type_name, fields } => {
                let mut map = HashMap::new();
                map.insert("__type__".to_string(), Value::make_str(type_name.as_str()));
                for (fname, fexpr) in fields {
                    let v = Box::pin(self.eval_expr(fexpr, env, ctx.clone())).await?;
                    map.insert(fname.clone(), v);
                }
                Ok(Value::make_map(map))
            }

            Expr::Slice { object, start, end } => {
                let obj = Box::pin(self.eval_expr(object, env, ctx.clone())).await?;
                let len = match &obj {
                    Value::List(l) => l.borrow().len() as i64,
                    Value::Str(s)  => s.chars().count() as i64,
                    _ => return Err(runtime_err!("slice requires list or string")),
                };
                let resolve = |e: &Option<Box<Expr>>, default: i64| -> i64 {
                    // Can't use async in closure; we'll use already-evaluated len
                    let _ = default;
                    let _ = e;
                    default // placeholder — see below
                };
                let _ = resolve; // unused
                let s = if let Some(e) = start {
                    let v = Box::pin(self.eval_expr(e, env, ctx.clone())).await?;
                    let i = v.as_int().unwrap_or(0);
                    if i < 0 { (len + i).max(0) as usize } else { i.min(len) as usize }
                } else { 0 };
                let e = if let Some(e) = end {
                    let v = Box::pin(self.eval_expr(e, env, ctx.clone())).await?;
                    let i = v.as_int().unwrap_or(len);
                    if i < 0 { (len + i).max(0) as usize } else { i.min(len) as usize }
                } else { len as usize };
                match obj {
                    Value::List(l) => {
                        let borrowed = l.borrow();
                        let end = e.min(borrowed.len());
                        let sliced: Vec<Value> = borrowed[s..end].to_vec();
                        Ok(Value::make_list(sliced))
                    }
                    Value::Str(str_rc) => {
                        let chars: Vec<char> = str_rc.chars().collect();
                        Ok(Value::make_str(chars[s..e.min(chars.len())].iter().collect::<String>()))
                    }
                    _ => unreachable!(),
                }
            }

            Expr::Method { object, method, args } => {
                let obj = Box::pin(self.eval_expr(object, env, ctx.clone())).await?;
                let mut evaluated_args = Vec::with_capacity(args.len());
                for a in args {
                    evaluated_args.push(Box::pin(self.eval_expr(a, env, ctx.clone())).await?);
                }
                self.call_method(obj, method, evaluated_args)
            }

            Expr::Field { object, field } => {
                let obj = Box::pin(self.eval_expr(object, env, ctx.clone())).await?;
                match &obj {
                    Value::Ctx(c)  => Ok(c.borrow().get_field(field)),
                    Value::Map(m)  => Ok(m.borrow().get(field.as_str()).cloned().unwrap_or(Value::Null)),
                    _ => Err(runtime_err!("cannot access field '{}' on {}", field, obj.type_name())),
                }
            }

            Expr::Index { object, index } => {
                let obj = Box::pin(self.eval_expr(object, env, ctx.clone())).await?;
                let idx = Box::pin(self.eval_expr(index, env, ctx)).await?;
                match (&obj, &idx) {
                    (Value::List(l), Value::Int(i)) => {
                        let l = l.borrow();
                        let i = if *i < 0 { (l.len() as i64 + i) as usize } else { *i as usize };
                        Ok(l.get(i).cloned().unwrap_or(Value::Null))
                    }
                    (Value::Str(s), Value::Int(i)) => {
                        // String character access — returns single-char string
                        let chars: Vec<char> = s.chars().collect();
                        let i = if *i < 0 { (chars.len() as i64 + i) as usize } else { *i as usize };
                        Ok(chars.get(i).map(|c| Value::make_str(c.to_string())).unwrap_or(Value::Null))
                    }
                    (Value::Map(m), _) => {
                        let key = idx.to_string();
                        Ok(m.borrow().get(&key).cloned().unwrap_or(Value::Null))
                    }
                    _ => Err(type_err!("list, map, or str", obj.type_name())),
                }
            }

            Expr::List(elems) => {
                let mut v = Vec::with_capacity(elems.len());
                for e in elems {
                    v.push(Box::pin(self.eval_expr(e, env, ctx.clone())).await?);
                }
                Ok(Value::make_list(v))
            }

            Expr::Map(pairs) => {
                let mut m = HashMap::new();
                for (k, v) in pairs {
                    let key = Box::pin(self.eval_expr(k, env, ctx.clone())).await?.to_string();
                    let val = Box::pin(self.eval_expr(v, env, ctx.clone())).await?;
                    m.insert(key, val);
                }
                Ok(Value::make_map(m))
            }
        }
    }

    // ── evaluate interpolation hole by re-parsing ─────────────────────────────

    async fn eval_hole(&self, src: &str, env: &mut Env, ctx: Option<Rc<RefCell<BotCtx>>>) -> GravResult<Value> {
        use crate::lexer::Lexer;
        use crate::parser::Parser;
        let tokens = Lexer::new(src).tokenize()?;
        let mut p = Parser::new(tokens);
        // Parse single expression
        // We parse a minimal expression via the public parse entry
        // For holes we treat as expression:
        let prog = p.parse_expr_pub()?;
        Box::pin(self.eval_expr(&prog, env, ctx)).await
    }

    // ── function call ─────────────────────────────────────────────────────────

    async fn call_fn(
        &self,
        name: &str,
        args: Vec<Value>,
        env:  &mut Env,
        ctx:  Option<Rc<RefCell<BotCtx>>>,
    ) -> GravResult<Value> {
        // map_list / filter_list need interpreter dispatch — handle before stdlib
        if name == "map_list" || name == "filter_list" {
            let list = match args.first() {
                Some(Value::List(l)) => l.clone(),
                _ => return Err(runtime_err!("{name}: first argument must be a list")),
            };
            let items: Vec<Value> = list.borrow().clone();
            let mut result = Vec::new();
            match args.get(1) {
                Some(Value::Str(s)) => {
                    let fn_name = s.as_ref().clone();
                    for item in items {
                        let v = Box::pin(self.call_fn(&fn_name, vec![item.clone()], env, ctx.clone())).await?;
                        if name == "map_list" { result.push(v); }
                        else if v.is_truthy() { result.push(item); }
                    }
                }
                Some(Value::Fn(fd)) => {
                    let fd = fd.clone();
                    for item in items {
                        let v = Box::pin(self.call_fn_def(fd.clone(), vec![item.clone()], env, ctx.clone())).await?;
                        if name == "map_list" { result.push(v); }
                        else if v.is_truthy() { result.push(item); }
                    }
                }
                _ => return Err(runtime_err!("{name}: second argument must be a function name or closure")),
            }
            return Ok(Value::make_list(result));
        }

        // stdlib first
        if let Some(v) = crate::stdlib::call_builtin(name, &args, &self.shared).await? {
            return Ok(v);
        }
        let fd = {
            let st = self.shared.lock().await;
            st.functions.get(name).cloned()
        };
        let fd = fd.ok_or_else(|| GravError::UndefinedFn(name.to_string()))?;
        Box::pin(self.call_fn_def(fd, args, env, ctx)).await
    }

    async fn call_fn_def(
        &self,
        fd:   Rc<FnDef>,
        args: Vec<Value>,
        env:  &mut Env,
        ctx:  Option<Rc<RefCell<BotCtx>>>,
    ) -> GravResult<Value> {
        // Fill missing args from defaults (#14)
        let mut full_args = args;
        for (i, param) in fd.params.iter().enumerate() {
            if i >= full_args.len() {
                if let Some(def_expr) = &param.default {
                    let v = Box::pin(self.eval_expr(def_expr, env, ctx.clone())).await?;
                    full_args.push(v);
                } else {
                    return Err(GravError::Arity {
                        name: fd.name.clone(),
                        expected: fd.params.len(),
                        got: full_args.len(),
                    });
                }
            }
        }
        if full_args.len() > fd.params.len() {
            return Err(GravError::Arity { name: fd.name.clone(), expected: fd.params.len(), got: full_args.len() });
        }
        let mut fn_env = Env::new();
        if let Some(c) = &ctx { fn_env.define("ctx", Value::Ctx(c.clone())); }
        for (param, val) in fd.params.iter().zip(full_args) {
            // #7 — runtime type check for each param
            if let Some(t) = &param.ty {
                typecheck(t, &val)?;
            }
            fn_env.define(&param.name, val);
        }
        // Push call stack frame
        {
            let mut st = self.shared.lock().await;
            st.call_stack.push((fd.name.clone(), fd.line));
        }
        let mut dummy_out = Vec::new();
        let result = Box::pin(self.exec_block(&fd.body, &mut fn_env, ctx, &mut dummy_out)).await;
        // Pop call stack frame (even on error)
        {
            let mut st = self.shared.lock().await;
            st.call_stack.pop();
        }
        match result {
            Ok(v)                    => Ok(v),
            Err(ExecErr::Return(v))  => Ok(v),
            Err(ExecErr::Err(e))     => Err(e),
            Err(_)                   => Ok(Value::Null),
        }
    }

    /// Format the current call stack as a readable traceback string.
    pub async fn format_traceback(&self) -> String {
        let st = self.shared.lock().await;
        if st.call_stack.is_empty() { return String::new(); }
        let mut out = String::from("\n  Stack trace (most recent call last):");
        for (name, line) in &st.call_stack {
            if *line > 0 {
                out.push_str(&format!("\n    in `{}` (defined at line {})", name, line));
            } else {
                out.push_str(&format!("\n    in `{}`", name));
            }
        }
        out
    }

    // ── method call on a value ────────────────────────────────────────────────

    fn call_method(&self, obj: Value, method: &str, args: Vec<Value>) -> GravResult<Value> {
        match &obj {
            Value::Str(s) => {
                match method {
                    "len"        => Ok(Value::Int(s.len() as i64)),
                    "to_upper"   => Ok(Value::make_str(s.to_uppercase())),
                    "to_lower"   => Ok(Value::make_str(s.to_lowercase())),
                    "trim"       => Ok(Value::make_str(s.trim().to_string())),
                    "starts_with"=> {
                        let p = args.first().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
                        Ok(Value::Bool(s.starts_with(p.as_str())))
                    }
                    "ends_with"  => {
                        let p = args.first().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
                        Ok(Value::Bool(s.ends_with(p.as_str())))
                    }
                    "contains"   => {
                        let p = args.first().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
                        Ok(Value::Bool(s.contains(p.as_str())))
                    }
                    "split"      => {
                        let sep = args.first().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
                        let parts: Vec<Value> = s.split(sep.as_str()).map(Value::make_str).collect();
                        Ok(Value::make_list(parts))
                    }
                    "replace"    => {
                        let from = args.get(0).and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
                        let to   = args.get(1).and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
                        Ok(Value::make_str(s.replace(from.as_str(), to.as_str())))
                    }
                    // #13 — new string methods
                    "slice" | "substring" => {
                        let chars: Vec<char> = s.chars().collect();
                        let len = chars.len() as i64;
                        let start = args.first().and_then(|v| v.as_int()).unwrap_or(0);
                        let end   = args.get(1).and_then(|v| v.as_int()).unwrap_or(len);
                        let s = if start < 0 { (len + start).max(0) } else { start.min(len) } as usize;
                        let e = if end   < 0 { (len + end  ).max(0) } else { end  .min(len) } as usize;
                        Ok(Value::make_str(chars[s..e.max(s)].iter().collect::<String>()))
                    }
                    "index_of" | "find" => {
                        let pat = args.first().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
                        Ok(s.find(pat.as_str())
                           .map(|i| Value::Int(i as i64))
                           .unwrap_or(Value::Int(-1)))
                    }
                    "chars" => {
                        let v: Vec<Value> = s.chars().map(|c| Value::make_str(c.to_string())).collect();
                        Ok(Value::make_list(v))
                    }
                    "repeat" => {
                        let n = args.first().and_then(|v| v.as_int()).unwrap_or(1).max(0) as usize;
                        Ok(Value::make_str(s.repeat(n)))
                    }
                    "is_empty" => Ok(Value::Bool(s.is_empty())),
                    _ => Err(runtime_err!("str has no method '{method}'")),
                }
            }
            Value::List(l) => {
                match method {
                    "len"    => Ok(Value::Int(l.borrow().len() as i64)),
                    "push"   => { l.borrow_mut().extend(args); Ok(Value::Null) }
                    "pop"    => Ok(l.borrow_mut().pop().unwrap_or(Value::Null)),
                    "first"  => Ok(l.borrow().first().cloned().unwrap_or(Value::Null)),
                    "last"   => Ok(l.borrow().last().cloned().unwrap_or(Value::Null)),
                    "join"   => {
                        let sep = args.first().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
                        let s: String = l.borrow().iter().map(|v| v.to_string()).collect::<Vec<_>>().join(&sep);
                        Ok(Value::make_str(s))
                    }
                    "contains" => {
                        let target = args.into_iter().next().unwrap_or(Value::Null);
                        Ok(Value::Bool(l.borrow().iter().any(|v| v == &target)))
                    }
                    _ => Err(runtime_err!("list has no method '{method}'")),
                }
            }
            Value::Map(m) => {
                match method {
                    "len"    => Ok(Value::Int(m.borrow().len() as i64)),
                    "keys"   => Ok(Value::make_list(m.borrow().keys().map(Value::make_str).collect())),
                    "values" => Ok(Value::make_list(m.borrow().values().cloned().collect())),
                    "has"    => {
                        let k = args.first().map(|v| v.to_string()).unwrap_or_default();
                        Ok(Value::Bool(m.borrow().contains_key(&k)))
                    }
                    "remove" => {
                        let k = args.first().map(|v| v.to_string()).unwrap_or_default();
                        Ok(m.borrow_mut().remove(&k).unwrap_or(Value::Null))
                    }
                    "entries" => {
                        let pairs: Vec<Value> = m.borrow().iter()
                            .map(|(k, v)| Value::make_list(vec![Value::make_str(k), v.clone()]))
                            .collect();
                        Ok(Value::make_list(pairs))
                    }
                    _ => Err(runtime_err!("map has no method '{method}'")),
                }
            }
            _ => Err(runtime_err!("{} has no method '{method}'", obj.type_name())),
        }
    }

    // ── pattern matching ──────────────────────────────────────────────────────

    /// Returns `Ok(Some(captures))` on match, `Ok(None)` on no-match.
    /// `captures[0]` = whole match, `captures[1..]` = capture groups ($1, $2, …).
    async fn match_pattern(&self, pattern: &Pattern, val: &Value) -> GravResult<Option<Vec<String>>> {
        match pattern {
            Pattern::Wild => Ok(Some(vec![])),
            Pattern::Lit(expr) => {
                let mut env = Env::new();
                let pv = self.eval_expr(expr, &mut env, None).await?;
                Ok(if &pv == val { Some(vec![]) } else { None })
            }
            Pattern::Regex { pattern, flags } => {
                let text = val.to_string();
                let re = {
                    let mut st = self.shared.lock().await;
                    st.get_or_compile_regex(pattern, flags)?
                };
                if let Some(caps) = re.captures(&text) {
                    let groups: Vec<String> = caps.iter()
                        .map(|m| m.map(|m| m.as_str().to_string()).unwrap_or_default())
                        .collect();
                    Ok(Some(groups))
                } else {
                    Ok(None)
                }
            }
            Pattern::Bind { name: _, inner } => Box::pin(self.match_pattern(inner, val)).await,
        }
    }

    // ── assignment target ─────────────────────────────────────────────────────

    async fn assign_target(
        &self,
        target: &Expr,
        val:    Value,
        env:    &mut Env,
        ctx:    Option<Rc<RefCell<BotCtx>>>,
    ) -> GravResult<()> {
        match target {
            Expr::Var(name) => {
                env.set(name, val);
                Ok(())
            }
            // state.field = val — write directly to bot_state
            Expr::Field { object, field } if matches!(object.as_ref(), Expr::StateRef) => {
                let mut st = self.shared.lock().await;
                st.bot_state.insert(field.clone(), val);
                Ok(())
            }
            Expr::Field { object, field } => {
                let obj = Box::pin(self.eval_expr(object, env, ctx)).await?;
                match obj {
                    Value::Map(m) => { m.borrow_mut().insert(field.clone(), val); Ok(()) }
                    Value::Ctx(_c) => Err(runtime_err!("cannot assign to ctx.{field}")),
                    _ => Err(runtime_err!("cannot assign to field '{field}'")),
                }
            }
            Expr::Index { object, index } => {
                let obj = Box::pin(self.eval_expr(object, env, ctx.clone())).await?;
                let idx = Box::pin(self.eval_expr(index, env, ctx)).await?;
                match obj {
                    Value::List(l) => {
                        if let Some(i) = idx.as_int() {
                            let mut l = l.borrow_mut();
                            let i = if i < 0 { (l.len() as i64 + i) as usize } else { i as usize };
                            if i < l.len() { l[i] = val; }
                        }
                        Ok(())
                    }
                    Value::Map(m) => {
                        m.borrow_mut().insert(idx.to_string(), val);
                        Ok(())
                    }
                    _ => Err(runtime_err!("cannot index-assign {}", obj.type_name())),
                }
            }
            _ => Err(runtime_err!("invalid assignment target")),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Binary operations
// ─────────────────────────────────────────────────────────────────────────────

fn apply_binop(op: BinOp, l: Value, r: Value) -> GravResult<Value> {
    match op {
        BinOp::Add => match (&l, &r) {
            (Value::Int(a),   Value::Int(b))   => Ok(Value::Int(a + b)),
            (Value::Float(a), Value::Float(b)) => Ok(Value::Float(a + b)),
            (Value::Int(a),   Value::Float(b)) => Ok(Value::Float(*a as f64 + b)),
            (Value::Float(a), Value::Int(b))   => Ok(Value::Float(a + *b as f64)),
            (Value::Str(a),   Value::Str(b))   => Ok(Value::make_str(format!("{a}{b}"))),
            (Value::Str(a),   _)               => Ok(Value::make_str(format!("{a}{r}"))),
            _ => Err(type_err!("+", format!("{} + {}", l.type_name(), r.type_name()))),
        },
        BinOp::Sub => numeric_op(l, r, |a, b| a - b, |a, b| a - b),
        BinOp::Mul => numeric_op(l, r, |a, b| a * b, |a, b| a * b),
        BinOp::Div => match (&l, &r) {
            (_, Value::Int(0))   => Err(runtime_err!("division by zero")),
            (_, Value::Float(f)) if *f == 0.0 => Err(runtime_err!("division by zero")),
            _ => numeric_op(l, r, |a, b| a / b, |a, b| a / b),
        },
        BinOp::Rem => numeric_op(l, r, |a, b| a % b, |a, b| a % b),
        BinOp::Pow => match (&l, &r) {
            (Value::Int(a),   Value::Int(b))   => Ok(Value::Int(a.pow(*b as u32))),
            _ => {
                let a = l.as_float().ok_or_else(|| type_err!("number", l.type_name()))?;
                let b = r.as_float().ok_or_else(|| type_err!("number", r.type_name()))?;
                Ok(Value::Float(a.powf(b)))
            }
        },
        BinOp::Eq  => Ok(Value::Bool(l == r)),
        BinOp::Ne  => Ok(Value::Bool(l != r)),
        BinOp::Lt  => Ok(Value::Bool(l.partial_cmp(&r) == Some(std::cmp::Ordering::Less))),
        BinOp::Gt  => Ok(Value::Bool(l.partial_cmp(&r) == Some(std::cmp::Ordering::Greater))),
        BinOp::Le  => Ok(Value::Bool(matches!(l.partial_cmp(&r), Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal)))),
        BinOp::Ge  => Ok(Value::Bool(matches!(l.partial_cmp(&r), Some(std::cmp::Ordering::Greater | std::cmp::Ordering::Equal)))),
        BinOp::And => Ok(Value::Bool(l.is_truthy() && r.is_truthy())),
        BinOp::Or  => Ok(Value::Bool(l.is_truthy() || r.is_truthy())),
        BinOp::RangeEx => {
            let start = l.as_int().ok_or_else(|| type_err!("int", l.type_name()))?;
            let end   = r.as_int().ok_or_else(|| type_err!("int", r.type_name()))?;
            Ok(Value::make_list((start..end).map(Value::Int).collect()))
        }
        BinOp::RangeIn => {
            let start = l.as_int().ok_or_else(|| type_err!("int", l.type_name()))?;
            let end   = r.as_int().ok_or_else(|| type_err!("int", r.type_name()))?;
            Ok(Value::make_list((start..=end).map(Value::Int).collect()))
        }
    }
}

fn numeric_op(
    l: Value, r: Value,
    int_op:   impl Fn(i64, i64) -> i64,
    float_op: impl Fn(f64, f64) -> f64,
) -> GravResult<Value> {
    match (&l, &r) {
        (Value::Int(a),   Value::Int(b))   => Ok(Value::Int(int_op(*a, *b))),
        (Value::Float(a), Value::Float(b)) => Ok(Value::Float(float_op(*a, *b))),
        (Value::Int(a),   Value::Float(b)) => Ok(Value::Float(float_op(*a as f64, *b))),
        (Value::Float(a), Value::Int(b))   => Ok(Value::Float(float_op(*a, *b as f64))),
        _ => Err(type_err!("number", format!("{} op {}", l.type_name(), r.type_name()))),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal control-flow error type (not public)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
enum ExecErr {
    Err(GravError),
    Return(Value),
    Break,
    Continue,
}

impl From<GravError> for ExecErr {
    fn from(e: GravError) -> Self { ExecErr::Err(e) }
}

// ─────────────────────────────────────────────────────────────────────────────
// Expose expr-only parse for string holes (used above)
// ─────────────────────────────────────────────────────────────────────────────

impl crate::parser::Parser {
    pub fn parse_expr_pub(&mut self) -> GravResult<Expr> {
        self.parse_expr()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public wrapper for exec_block (used by bot scheduler tasks)
// ─────────────────────────────────────────────────────────────────────────────

impl Interpreter {
    pub async fn exec_block_pub(
        &self,
        stmts:   &[Stmt],
        env:     &mut Env,
        ctx:     Option<Rc<RefCell<crate::value::BotCtx>>>,
        outputs: &mut Vec<BotOutput>,
    ) -> Result<crate::value::Value, String> {
        match self.exec_block(stmts, env, ctx, outputs).await {
            Ok(v)  => Ok(v),
            Err(e) => Err(format!("{e:?}")),
        }
    }
}
