/// Minimal Language Server Protocol server for Gravitix (.grav files).
///
/// Protocol: JSON-RPC 2.0 over stdin/stdout with Content-Length headers.
/// Implements:
///   - initialize / initialized / shutdown / exit
///   - textDocument/didOpen, didChange, didClose
///   - textDocument/completion  — keywords + builtins
///   - textDocument/hover        — basic keyword descriptions
///   - textDocument/publishDiagnostics — parse errors

use std::io::{self, BufRead, Write};
use std::collections::HashMap;
use serde_json::{json, Value as JVal};

// ─────────────────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────────────────

pub fn run_lsp() {
    let stdin  = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();

    let mut docs: HashMap<String, String> = HashMap::new();

    let mut reader = stdin.lock();

    loop {
        // Read Content-Length header
        let mut header = String::new();
        if reader.read_line(&mut header).unwrap_or(0) == 0 { break; }
        let header = header.trim();
        if !header.starts_with("Content-Length:") { continue; }
        let len: usize = header["Content-Length:".len()..].trim().parse().unwrap_or(0);

        // Consume blank line after header
        let mut blank = String::new();
        reader.read_line(&mut blank).ok();

        // Read body
        let mut body = vec![0u8; len];
        use std::io::Read;
        if reader.read_exact(&mut body).is_err() { break; }
        let body = match String::from_utf8(body) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let msg: JVal = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let method = msg["method"].as_str().unwrap_or("");
        let id     = msg.get("id").cloned();
        let params = msg.get("params").cloned().unwrap_or(JVal::Null);

        match method {
            "initialize" => {
                let response = make_response(id, json!({
                    "capabilities": {
                        "textDocumentSync": 1,
                        "completionProvider": {
                            "triggerCharacters": [".", " "]
                        },
                        "hoverProvider": true
                    },
                    "serverInfo": {
                        "name": "gravitix-lsp",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                }));
                send(&mut out, &response);
            }

            "initialized" | "$/cancelRequest" => {}

            "shutdown" => {
                let response = make_response(id, JVal::Null);
                send(&mut out, &response);
            }

            "exit" => break,

            "textDocument/didOpen" => {
                if let (Some(uri), Some(text)) = (
                    params["textDocument"]["uri"].as_str(),
                    params["textDocument"]["text"].as_str(),
                ) {
                    let uri = uri.to_string();
                    let text = text.to_string();
                    let diags = compute_diagnostics(&text);
                    docs.insert(uri.clone(), text);
                    publish_diagnostics(&mut out, &uri, diags);
                }
            }

            "textDocument/didChange" => {
                if let Some(uri) = params["textDocument"]["uri"].as_str() {
                    if let Some(change) = params["contentChanges"].as_array().and_then(|a| a.last()) {
                        if let Some(text) = change["text"].as_str() {
                            let uri = uri.to_string();
                            let text = text.to_string();
                            let diags = compute_diagnostics(&text);
                            docs.insert(uri.clone(), text);
                            publish_diagnostics(&mut out, &uri, diags);
                        }
                    }
                }
            }

            "textDocument/didClose" => {
                if let Some(uri) = params["textDocument"]["uri"].as_str() {
                    docs.remove(uri);
                }
            }

            "textDocument/completion" => {
                let items = completion_items();
                let response = make_response(id, json!({ "isIncomplete": false, "items": items }));
                send(&mut out, &response);
            }

            "textDocument/hover" => {
                let text = params["textDocument"]["uri"].as_str()
                    .and_then(|u| docs.get(u))
                    .cloned()
                    .unwrap_or_default();
                let line  = params["position"]["line"].as_u64().unwrap_or(0) as usize;
                let col   = params["position"]["character"].as_u64().unwrap_or(0) as usize;
                let word  = word_at(&text, line, col);
                let hover = hover_for(&word);
                let response = if let Some(md) = hover {
                    make_response(id, json!({
                        "contents": { "kind": "markdown", "value": md }
                    }))
                } else {
                    make_response(id, JVal::Null)
                };
                send(&mut out, &response);
            }

            _ => {
                // Unknown request — send error only if it has an id (i.e., is a request not a notification)
                if let Some(id) = id {
                    let response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": { "code": -32601, "message": "Method not found" }
                    });
                    send(&mut out, &response);
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Diagnostics (syntax checking)
// ─────────────────────────────────────────────────────────────────────────────

fn compute_diagnostics(src: &str) -> Vec<JVal> {
    use crate::lexer::Lexer;
    use crate::parser::Parser;

    let lex_result = Lexer::new(src).tokenize();
    let tokens = match lex_result {
        Ok(t) => t,
        Err(e) => {
            return vec![error_diag(e.to_string(), 0, 0)];
        }
    };
    match Parser::new(tokens).parse() {
        Ok(_) => vec![],
        Err(crate::error::GravError::Syntax { line, col, msg }) => {
            vec![error_diag(msg, (line.saturating_sub(1)) as u64, (col.saturating_sub(1)) as u64)]
        }
        Err(e) => vec![error_diag(e.to_string(), 0, 0)],
    }
}

fn error_diag(msg: String, line: u64, col: u64) -> JVal {
    json!({
        "range": {
            "start": { "line": line, "character": col },
            "end":   { "line": line, "character": col + 1 }
        },
        "severity": 1,
        "source": "gravitix",
        "message": msg
    })
}

fn publish_diagnostics(out: &mut impl Write, uri: &str, diags: Vec<JVal>) {
    let notif = json!({
        "jsonrpc": "2.0",
        "method": "textDocument/publishDiagnostics",
        "params": { "uri": uri, "diagnostics": diags }
    });
    send(out, &notif);
}

// ─────────────────────────────────────────────────────────────────────────────
// Completions
// ─────────────────────────────────────────────────────────────────────────────

fn completion_items() -> Vec<JVal> {
    const KEYWORDS: &[(&str, &str)] = &[
        ("fn",       "Function definition"),
        ("on",       "Message handler: on /cmd { … }"),
        ("flow",     "Multi-step dialogue flow"),
        ("state",    "Persistent bot state block"),
        ("every",    "Periodic scheduler: every 5 min { … }"),
        ("at",       "Time-based scheduler: at \"08:00\" { … }"),
        ("let",      "Variable declaration"),
        ("emit",     "Send a message to the current chat"),
        ("return",   "Return a value from a function"),
        ("if",       "Conditional: if cond { … }"),
        ("elif",     "Else-if branch"),
        ("else",     "Else branch"),
        ("while",    "While loop"),
        ("for",      "For-in loop: for x in list { … }"),
        ("match",    "Pattern match"),
        ("run",      "Run a flow: run flow name"),
        ("try",      "Try/catch: try { … } catch e { … }"),
        ("keyboard", "Send inline keyboard"),
        ("edit",     "Edit a message"),
        ("answer",   "Answer a callback query"),
        ("struct",   "Struct definition"),
        ("use",      "Include another script: use \"file.grav\""),
        ("test",     "Test block: test \"name\" { … }"),
        ("wait",     "Wait for user reply inside a flow"),
        ("guard",    "Handler guard condition"),
        ("callback", "Callback query trigger"),
        ("break",    "Break out of a loop"),
        ("continue", "Continue to next loop iteration"),
        ("null",     "Null literal"),
        ("true",     "Boolean true"),
        ("false",    "Boolean false"),
    ];

    const BUILTINS: &[(&str, &str)] = &[
        ("len",          "len(v) — length of string/list/map"),
        ("type_of",      "type_of(v) — returns type name as string"),
        ("to_int",       "to_int(v) — convert to integer"),
        ("to_float",     "to_float(v) — convert to float"),
        ("to_str",       "to_str(v) — convert to string"),
        ("print",        "print(v…) — print to stdout"),
        ("log",          "log(v…) — print to stderr"),
        ("random",       "random() — random float [0,1)"),
        ("rand_int",     "rand_int(min, max) — random integer"),
        ("floor",        "floor(n) — round down"),
        ("ceil",         "ceil(n) — round up"),
        ("abs",          "abs(n) — absolute value"),
        ("min",          "min(a, b) — minimum"),
        ("max",          "max(a, b) — maximum"),
        ("map_list",     "map_list(list, fn) — transform each element"),
        ("filter_list",  "filter_list(list, fn) — keep elements where fn returns true"),
        ("fetch",        "fetch(url, method?, body?, headers?) — HTTP request"),
        ("json_parse",   "json_parse(str) — parse JSON string"),
        ("json_encode",  "json_encode(val) — encode value as JSON"),
        ("state_save",   "state_save() — persist state to disk"),
        ("state_load",   "state_load() — load state from disk"),
        ("assert",       "assert(cond, msg?) — test assertion"),
        ("assert_eq",    "assert_eq(a, b, msg?) — equality assertion"),
        ("assert_ne",    "assert_ne(a, b, msg?) — inequality assertion"),
        ("now_unix",     "now_unix() — current Unix timestamp"),
        ("format_date",  "format_date(ts, fmt?) — format Unix timestamp"),
        ("sleep_ms",     "sleep_ms(ms) — sleep for milliseconds"),
    ];

    let mut items: Vec<JVal> = Vec::new();

    for (label, detail) in KEYWORDS {
        items.push(json!({
            "label": label,
            "kind": 14,  // Keyword
            "detail": detail,
            "insertText": label
        }));
    }
    for (label, detail) in BUILTINS {
        items.push(json!({
            "label": label,
            "kind": 3,   // Function
            "detail": detail,
            "insertText": label
        }));
    }
    items
}

// ─────────────────────────────────────────────────────────────────────────────
// Hover
// ─────────────────────────────────────────────────────────────────────────────

fn hover_for(word: &str) -> Option<String> {
    let map: &[(&str, &str)] = &[
        ("fn",       "**fn** — define a function\n```\nfn name(param: type) -> ret { … }\n```"),
        ("on",       "**on** — message handler\n```\non /start { emit \"Hello!\" }\non msg { emit ctx.text }\n```"),
        ("flow",     "**flow** — multi-step dialogue\n```\nflow my_flow {\n    emit \"What is your name?\"\n    let name = wait msg\n}\n```"),
        ("state",    "**state** — persistent bot-level state\n```\nstate { count: int = 0 }\n```"),
        ("every",    "**every** — periodic scheduler\n```\nevery 30 min { emit \"Tick!\" }\n```"),
        ("at",       "**at** — time-based scheduler\n```\nat \"09:00\" { emit \"Good morning!\" }\n```"),
        ("emit",     "**emit** — send message to current chat\n```\nemit \"Hello!\"\nemit \"Score: {score}\"\n```"),
        ("wait",     "**wait msg** — pause flow and wait for next user message\n```\nlet reply = wait msg\n```"),
        ("keyboard", "**keyboard** — send inline keyboard\n```\nkeyboard \"Choose:\", [[\"Yes\", \"yes\"], [\"No\", \"no\"]]\n```"),
        ("callback", "**callback** trigger — handle inline button presses\n```\non callback \"yes\" { emit \"You chose yes\" }\n```"),
        ("try",      "**try/catch** — error handling\n```\ntry { fetch(url) } catch e { emit \"Error: {e}\" }\n```"),
        ("match",    "**match** — pattern matching\n```\nmatch ctx.text {\n    /hello/i => emit \"Hi!\"\n    _ => emit \"?\"\n}\n```"),
        ("test",     "**test** — test block (run with `gravitix test file.grav`)\n```\ntest \"addition\" {\n    assert_eq(1 + 1, 2)\n}\n```"),
        ("assert",       "`assert(cond, msg?)` — fails test if condition is false"),
        ("assert_eq",    "`assert_eq(a, b, msg?)` — fails test if a != b"),
        ("assert_ne",    "`assert_ne(a, b, msg?)` — fails test if a == b"),
        ("fetch",        "`fetch(url, method?, body?, headers?)` — HTTP request, returns parsed JSON or string"),
        ("json_parse",   "`json_parse(str)` — parse a JSON string into a Gravitix value"),
        ("json_encode",  "`json_encode(val)` — encode a value as a JSON string"),
        ("map_list",     "`map_list(list, fn)` — transform each element, returns new list"),
        ("filter_list",  "`filter_list(list, fn)` — keep elements where fn(x) is truthy"),
    ];
    map.iter().find(|(k, _)| *k == word).map(|(_, v)| v.to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// Utilities
// ─────────────────────────────────────────────────────────────────────────────

fn word_at(src: &str, line: usize, col: usize) -> String {
    let lines: Vec<&str> = src.lines().collect();
    let line_str = lines.get(line).copied().unwrap_or("");
    let chars: Vec<char> = line_str.chars().collect();
    let col = col.min(chars.len());
    let start = chars[..col].iter().rposition(|c| !c.is_alphanumeric() && *c != '_')
        .map(|i| i + 1).unwrap_or(0);
    let end = chars[col..].iter().position(|c| !c.is_alphanumeric() && *c != '_')
        .map(|i| col + i).unwrap_or(chars.len());
    chars[start..end].iter().collect()
}

fn make_response(id: Option<JVal>, result: JVal) -> JVal {
    json!({
        "jsonrpc": "2.0",
        "id": id.unwrap_or(JVal::Null),
        "result": result
    })
}

fn send(out: &mut impl Write, msg: &JVal) {
    let body = serde_json::to_string(msg).unwrap_or_default();
    write!(out, "Content-Length: {}\r\n\r\n{}", body.len(), body).ok();
    out.flush().ok();
}
