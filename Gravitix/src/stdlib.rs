use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::interpreter::SharedState;
use crate::value::Value;
use crate::error::GravResult;
use crate::runtime_err;

/// Returns `Some(value)` if the function is a builtin, `None` if not found.
pub async fn call_builtin(
    name:   &str,
    args:   &[Value],
    shared: &Arc<Mutex<SharedState>>,
) -> GravResult<Option<Value>> {
    let v = match name {
        // ── Type conversion ───────────────────────────────────────────────────
        "int" | "parse_int" => {
            let s = args.first().map(|v| v.to_string()).unwrap_or_default();
            Ok(Value::Int(s.trim().parse::<i64>()
                .map_err(|_| runtime_err!("cannot convert '{}' to int", s))?))
        }
        "float" | "parse_float" => {
            let s = args.first().map(|v| v.to_string()).unwrap_or_default();
            Ok(Value::Float(s.trim().parse::<f64>()
                .map_err(|_| runtime_err!("cannot convert '{}' to float", s))?))
        }
        "str" | "to_str" => {
            Ok(Value::make_str(args.first().map(|v| v.to_string()).unwrap_or_default()))
        }
        "bool" => {
            Ok(Value::Bool(args.first().map(|v| v.is_truthy()).unwrap_or(false)))
        }

        // ── String operations ─────────────────────────────────────────────────
        "trim" => {
            let s = get_str(args, 0, "trim")?;
            Ok(Value::make_str(s.trim().to_string()))
        }
        "lowercase" | "to_lower" => {
            let s = get_str(args, 0, "lowercase")?;
            Ok(Value::make_str(s.to_lowercase()))
        }
        "uppercase" | "to_upper" => {
            let s = get_str(args, 0, "uppercase")?;
            Ok(Value::make_str(s.to_uppercase()))
        }
        "len" => {
            match args.first() {
                Some(Value::Str(s))    => Ok(Value::Int(s.len() as i64)),
                Some(Value::List(l))   => Ok(Value::Int(l.borrow().len() as i64)),
                Some(Value::Map(m))    => Ok(Value::Int(m.borrow().len() as i64)),
                Some(v) => Err(runtime_err!("len: cannot get length of {}", v.type_name())),
                None    => Err(runtime_err!("len: expected 1 argument")),
            }
        }
        "split" => {
            let s   = get_str(args, 0, "split")?;
            let sep = get_str(args, 1, "split").unwrap_or_default();
            let sep = if sep.is_empty() { " ".to_string() } else { sep };
            Ok(Value::make_list(s.split(sep.as_str()).map(Value::make_str).collect()))
        }
        "join" => {
            let list = match args.first() {
                Some(Value::List(l)) => l.borrow().iter().map(|v| v.to_string()).collect::<Vec<_>>(),
                _ => return Err(runtime_err!("join: expected list as first arg")),
            };
            let sep = get_str(args, 1, "join").unwrap_or_default();
            Ok(Value::make_str(list.join(&sep)))
        }
        "contains" => {
            match args.first() {
                Some(Value::Str(s)) => {
                    let needle = get_str(args, 1, "contains")?;
                    Ok(Value::Bool(s.contains(needle.as_str())))
                }
                Some(Value::List(l)) => {
                    let target = args.get(1).cloned().unwrap_or(Value::Null);
                    Ok(Value::Bool(l.borrow().iter().any(|v| v == &target)))
                }
                _ => Err(runtime_err!("contains: expected str or list")),
            }
        }
        "replace" => {
            let s    = get_str(args, 0, "replace")?;
            let from = get_str(args, 1, "replace")?;
            let to   = get_str(args, 2, "replace").unwrap_or_default();
            Ok(Value::make_str(s.replace(from.as_str(), to.as_str())))
        }
        "sanitize" => {
            // Remove control characters / HTML special chars
            let s = get_str(args, 0, "sanitize")?;
            let clean: String = s.chars()
                .map(|c| match c { '<' => '[', '>' => ']', '&' => '+', _ => c })
                .filter(|c| !c.is_control())
                .collect();
            Ok(Value::make_str(clean))
        }

        // ── Math ──────────────────────────────────────────────────────────────
        "abs" => {
            match args.first() {
                Some(Value::Int(n))   => Ok(Value::Int(n.abs())),
                Some(Value::Float(f)) => Ok(Value::Float(f.abs())),
                _ => Err(runtime_err!("abs: expected number")),
            }
        }
        "min" => {
            let a = get_num(args, 0, "min")?;
            let b = get_num(args, 1, "min")?;
            Ok(if a <= b { args[0].clone() } else { args[1].clone() })
        }
        "max" => {
            let a = get_num(args, 0, "max")?;
            let b = get_num(args, 1, "max")?;
            Ok(if a >= b { args[0].clone() } else { args[1].clone() })
        }
        "floor"  => { let f = get_float(args, 0, "floor")?;  Ok(Value::Int(f.floor() as i64)) }
        "ceil"   => { let f = get_float(args, 0, "ceil")?;   Ok(Value::Int(f.ceil()  as i64)) }
        "round"  => { let f = get_float(args, 0, "round")?;  Ok(Value::Int(f.round() as i64)) }
        "sqrt"   => { let f = get_float(args, 0, "sqrt")?;   Ok(Value::Float(f.sqrt())) }
        "pow"    => {
            let base = get_float(args, 0, "pow")?;
            let exp  = get_float(args, 1, "pow")?;
            Ok(Value::Float(base.powf(exp)))
        }
        "random" => {
            // XorShift64 with atomic state — each call advances the PRNG correctly
            use std::sync::atomic::{AtomicU64, Ordering};
            use std::time::{SystemTime, UNIX_EPOCH};
            static SEED: AtomicU64 = AtomicU64::new(0);
            let mut s = SEED.load(Ordering::Relaxed);
            if s == 0 {
                s = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_nanos() as u64 ^ d.as_secs().wrapping_mul(0x9e3779b97f4a7c15))
                    .unwrap_or(0x853c49e6748fea9b);
                if s == 0 { s = 0x853c49e6748fea9b; }
            }
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            SEED.store(s, Ordering::Relaxed);
            let max = args.first().and_then(|v| v.as_int()).unwrap_or(100).max(1);
            Ok(Value::Int((s % max as u64) as i64))
        }

        // ── List operations ───────────────────────────────────────────────────
        "range" => {
            let start = args.first().and_then(|v| v.as_int()).unwrap_or(0);
            let end   = args.get(1).and_then(|v| v.as_int()).unwrap_or(10);
            let step  = args.get(2).and_then(|v| v.as_int()).unwrap_or(1);
            if step == 0 { return Err(runtime_err!("range: step cannot be 0")); }
            let mut v = Vec::new();
            let mut i = start;
            while if step > 0 { i < end } else { i > end } {
                v.push(Value::Int(i));
                i += step;
            }
            Ok(Value::make_list(v))
        }
        "push" => {
            if let Some(Value::List(l)) = args.first() {
                for v in &args[1..] { l.borrow_mut().push(v.clone()); }
                Ok(Value::Null)
            } else { Err(runtime_err!("push: expected list as first arg")) }
        }
        "pop" => {
            if let Some(Value::List(l)) = args.first() {
                Ok(l.borrow_mut().pop().unwrap_or(Value::Null))
            } else { Err(runtime_err!("pop: expected list")) }
        }
        "reverse" => {
            if let Some(Value::List(l)) = args.first() {
                let rev: Vec<Value> = l.borrow().iter().cloned().rev().collect();
                Ok(Value::make_list(rev))
            } else { Err(runtime_err!("reverse: expected list")) }
        }
        "map_list" | "filter_list" => {
            // Handled as a special case in Interpreter::call_fn (needs function dispatch).
            // Returning None passes it through to the interpreter layer.
            return Ok(None);
        }

        // ── State helpers ─────────────────────────────────────────────────────
        "state_get" => {
            let key = get_str(args, 0, "state_get")?;
            let st  = shared.lock().await;
            Ok(st.bot_state.get(&key).cloned().unwrap_or(Value::Null))
        }
        "state_set" => {
            let key = get_str(args, 0, "state_set")?;
            let val = args.get(1).cloned().unwrap_or(Value::Null);
            shared.lock().await.bot_state.insert(key, val);
            Ok(Value::Null)
        }
        "state_del" => {
            let key = get_str(args, 0, "state_del")?;
            shared.lock().await.bot_state.remove(&key);
            Ok(Value::Null)
        }

        // ── I/O and bot utils ─────────────────────────────────────────────────
        "print" => {
            let s = args.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(" ");
            println!("{s}");
            Ok(Value::Null)
        }
        "log" => {
            let s = args.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(" ");
            eprintln!("[gravitix] {s}");
            Ok(Value::Null)
        }
        "type_of" => {
            Ok(Value::make_str(args.first().map(|v| v.type_name()).unwrap_or("null")))
        }
        // ── Test assertions ───────────────────────────────────────────────────
        "assert" => {
            let cond = args.first().map(|v| v.is_truthy()).unwrap_or(false);
            if !cond {
                let msg = args.get(1).map(|v| v.to_string())
                    .unwrap_or_else(|| "assertion failed".to_string());
                return Err(crate::error::GravError::Runtime(msg));
            }
            Ok(Value::Null)
        }
        "assert_eq" => {
            let a = args.first().cloned().unwrap_or(Value::Null);
            let b = args.get(1).cloned().unwrap_or(Value::Null);
            if a != b {
                let msg = args.get(2).map(|v| v.to_string())
                    .unwrap_or_else(|| format!("assert_eq failed: {:?} != {:?}", a, b));
                return Err(crate::error::GravError::Runtime(msg));
            }
            Ok(Value::Null)
        }
        "assert_ne" => {
            let a = args.first().cloned().unwrap_or(Value::Null);
            let b = args.get(1).cloned().unwrap_or(Value::Null);
            if a == b {
                let msg = args.get(2).map(|v| v.to_string())
                    .unwrap_or_else(|| format!("assert_ne failed: both equal {:?}", a));
                return Err(crate::error::GravError::Runtime(msg));
            }
            Ok(Value::Null)
        }

        "is_null"   => Ok(Value::Bool(matches!(args.first(), Some(Value::Null) | None))),
        "is_int"    => Ok(Value::Bool(matches!(args.first(), Some(Value::Int(_))))),
        "is_float"  => Ok(Value::Bool(matches!(args.first(), Some(Value::Float(_))))),
        "is_str"    => Ok(Value::Bool(matches!(args.first(), Some(Value::Str(_))))),
        "is_list"   => Ok(Value::Bool(matches!(args.first(), Some(Value::List(_))))),
        "is_map"    => Ok(Value::Bool(matches!(args.first(), Some(Value::Map(_))))),
        "is_bool"   => Ok(Value::Bool(matches!(args.first(), Some(Value::Bool(_))))),

        // ── Time ──────────────────────────────────────────────────────────────
        "now_unix" => {
            use std::time::{SystemTime, UNIX_EPOCH};
            let ts = SystemTime::now().duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64).unwrap_or(0);
            Ok(Value::Int(ts))
        }
        "now_str" => {
            // Simple ISO-like timestamp without external crate
            use std::time::{SystemTime, UNIX_EPOCH};
            let ts = SystemTime::now().duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs()).unwrap_or(0);
            let s  = secs_to_date(ts);
            Ok(Value::make_str(s))
        }

        // ── Format ────────────────────────────────────────────────────────────
        "format_number" => {
            match args.first() {
                Some(Value::Int(n))   => Ok(Value::make_str(format_with_commas(*n))),
                Some(Value::Float(f)) => Ok(Value::make_str(format!("{f:.2}"))),
                _ => Err(runtime_err!("format_number: expected number")),
            }
        }
        "pad_left" => {
            let s     = get_str(args, 0, "pad_left")?;
            let width = args.get(1).and_then(|v| v.as_int()).unwrap_or(0) as usize;
            let pad   = get_str(args, 2, "pad_left").unwrap_or_else(|_| " ".to_string());
            let pad_ch = pad.chars().next().unwrap_or(' ');
            Ok(Value::make_str(format!("{:>width$}", s, width = width)
                .replacen(' ', &pad_ch.to_string(), 1)))
        }

        // ── HTTP ─────────────────────────────────────────────────────────────
        "fetch" => {
            let url    = get_str(args, 0, "fetch")?;
            let method = args.get(1).and_then(|v| v.as_str().map(str::to_string))
                             .unwrap_or_else(|| "GET".to_string());
            let body   = args.get(2).filter(|v| !matches!(v, Value::Null))
                             .map(|v| v.to_string());
            let headers: Vec<(String, String)> = match args.get(3) {
                Some(Value::Map(m)) => m.borrow().iter()
                    .map(|(k, v)| (k.clone(), v.to_string()))
                    .collect(),
                _ => vec![],
            };
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .map_err(|e| runtime_err!("fetch: client build: {e}"))?;
            let mut req = match method.to_uppercase().as_str() {
                "POST"   => client.post(&url),
                "PUT"    => client.put(&url),
                "DELETE" => client.delete(&url),
                "PATCH"  => client.patch(&url),
                _        => client.get(&url),
            };
            req = req.header("User-Agent", "gravitix-bot/1.0");
            for (k, v) in headers { req = req.header(k, v); }
            if let Some(b) = body {
                req = req.header("Content-Type", "application/json").body(b);
            }
            let resp = req.send().await.map_err(|e| runtime_err!("fetch: {e}"))?;
            let text = resp.text().await.map_err(|e| runtime_err!("fetch read: {e}"))?;
            Ok(Value::make_str(text))
        }

        // ── JSON ─────────────────────────────────────────────────────────────
        "json_parse" => {
            let s = get_str(args, 0, "json_parse")?;
            let jv: serde_json::Value = serde_json::from_str(&s)
                .map_err(|e| runtime_err!("json_parse: {e}"))?;
            Ok(json_to_value(jv))
        }

        "json_encode" => {
            let v  = args.first().cloned().unwrap_or(Value::Null);
            let jv = value_to_json(&v);
            Ok(Value::make_str(serde_json::to_string(&jv).unwrap_or_default()))
        }

        "json_encode_pretty" => {
            let v  = args.first().cloned().unwrap_or(Value::Null);
            let jv = value_to_json(&v);
            Ok(Value::make_str(serde_json::to_string_pretty(&jv).unwrap_or_default()))
        }

        // ── State persistence ─────────────────────────────────────────────────
        "state_save" => {
            let st = shared.lock().await;
            if let Some(ref path) = st.state_file {
                let map: serde_json::Map<String, serde_json::Value> = st.bot_state.iter()
                    .map(|(k, v)| (k.clone(), value_to_json(v)))
                    .collect();
                let json = serde_json::to_string_pretty(&serde_json::Value::Object(map))
                    .unwrap_or_default();
                let path = path.clone();
                drop(st);
                std::fs::write(&path, json)
                    .map_err(|e| runtime_err!("state_save: {e}"))?;
            }
            Ok(Value::Null)
        }

        "state_load" => {
            let path = { shared.lock().await.state_file.clone() };
            if let Some(path) = path {
                if let Ok(text) = std::fs::read_to_string(&path) {
                    if let Ok(serde_json::Value::Object(map)) =
                        serde_json::from_str::<serde_json::Value>(&text)
                    {
                        let mut st = shared.lock().await;
                        for (k, v) in map { st.bot_state.insert(k, json_to_value(v)); }
                    }
                }
            }
            Ok(Value::Null)
        }

        // ── Cryptography ──────────────────────────────────────────────────────
        "base64_encode" => {
            use base64::{Engine as _, engine::general_purpose};
            let s = get_str(args, 0, "base64_encode")?;
            Ok(Value::make_str(general_purpose::STANDARD.encode(s.as_bytes())))
        }
        "base64_decode" => {
            use base64::{Engine as _, engine::general_purpose};
            let s = get_str(args, 0, "base64_decode")?;
            let decoded = general_purpose::STANDARD.decode(s.trim())
                .map_err(|e| runtime_err!("base64_decode: {e}"))?;
            Ok(Value::make_str(String::from_utf8_lossy(&decoded).into_owned()))
        }
        "base64_decode_bytes" => {
            use base64::{Engine as _, engine::general_purpose};
            let s = get_str(args, 0, "base64_decode_bytes")?;
            let decoded = general_purpose::STANDARD.decode(s.trim())
                .map_err(|e| runtime_err!("base64_decode_bytes: {e}"))?;
            Ok(Value::make_list(decoded.into_iter().map(|b| Value::Int(b as i64)).collect()))
        }
        "hash_md5" => {
            let s = get_str(args, 0, "hash_md5")?;
            let digest = md5::compute(s.as_bytes());
            Ok(Value::make_str(format!("{:x}", digest)))
        }
        "hash_sha256" => {
            use sha2::{Sha256, Digest};
            let s = get_str(args, 0, "hash_sha256")?;
            let hash = Sha256::digest(s.as_bytes());
            Ok(Value::make_str(hex::encode(hash)))
        }
        "hash_sha512" => {
            use sha2::{Sha512, Digest};
            let s = get_str(args, 0, "hash_sha512")?;
            let hash = Sha512::digest(s.as_bytes());
            Ok(Value::make_str(hex::encode(hash)))
        }
        "hmac_sha256" => {
            use hmac::{Hmac, Mac};
            use sha2::Sha256;
            let key = get_str(args, 0, "hmac_sha256")?;
            let msg = get_str(args, 1, "hmac_sha256")?;
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.as_bytes())
                .map_err(|e| runtime_err!("hmac_sha256: {e}"))?;
            mac.update(msg.as_bytes());
            Ok(Value::make_str(hex::encode(mac.finalize().into_bytes())))
        }
        "hex_encode" => {
            let s = get_str(args, 0, "hex_encode")?;
            Ok(Value::make_str(hex::encode(s.as_bytes())))
        }
        "hex_decode" => {
            let s = get_str(args, 0, "hex_decode")?;
            let bytes = hex::decode(s.trim()).map_err(|e| runtime_err!("hex_decode: {e}"))?;
            Ok(Value::make_str(String::from_utf8_lossy(&bytes).into_owned()))
        }

        // ── Date parsing & arithmetic ──────────────────────────────────────────
        "parse_date" => {
            let s = get_str(args, 0, "parse_date")?;
            let ts = parse_date_str(&s)
                .ok_or_else(|| runtime_err!("parse_date: cannot parse '{s}' — use YYYY-MM-DD or YYYY-MM-DD HH:MM:SS"))?;
            Ok(Value::Int(ts))
        }
        "date_add" => {
            let ts     = args.first().and_then(|v| v.as_int()).unwrap_or(0);
            let amount = args.get(1).and_then(|v| v.as_int()).unwrap_or(0);
            let unit   = get_str(args, 2, "date_add")?;
            let delta  = match unit.to_lowercase().as_str() {
                "second" | "seconds" | "sec" | "s" => amount,
                "minute" | "minutes" | "min" | "m" => amount * 60,
                "hour"   | "hours"   | "h"          => amount * 3600,
                "day"    | "days"    | "d"           => amount * 86400,
                "week"   | "weeks"   | "w"           => amount * 604_800,
                "month"  | "months"                  => {
                    let (y, mo, d, h, mi, s) = utc_components(ts as u64);
                    let total_months = (y as i64 * 12 + mo as i64 - 1) + amount;
                    let ny  = (total_months / 12) as u64;
                    let nmo = ((total_months % 12) + 1) as u8;
                    return Ok(Some(Value::Int(gregorian_to_unix(ny, nmo, d as u8, h as u8, mi as u8, s as u8))));
                }
                "year" | "years" | "y" => {
                    let (y, mo, d, h, mi, s) = utc_components(ts as u64);
                    let ny = ((y as i64) + amount) as u64;
                    return Ok(Some(Value::Int(gregorian_to_unix(ny, mo as u8, d as u8, h as u8, mi as u8, s as u8))));
                }
                _ => return Err(runtime_err!("date_add: unknown unit '{unit}'")),
            };
            Ok(Value::Int(ts + delta))
        }
        "date_diff" => {
            let ts1  = args.first().and_then(|v| v.as_int()).unwrap_or(0);
            let ts2  = args.get(1).and_then(|v| v.as_int()).unwrap_or(0);
            let unit = get_str(args, 2, "date_diff")?;
            let diff_secs = ts2 - ts1;
            let result = match unit.to_lowercase().as_str() {
                "second" | "seconds" | "sec" | "s" => diff_secs,
                "minute" | "minutes" | "min" | "m" => diff_secs / 60,
                "hour"   | "hours"   | "h"          => diff_secs / 3600,
                "day"    | "days"    | "d"           => diff_secs / 86400,
                "week"   | "weeks"   | "w"           => diff_secs / 604_800,
                _ => return Err(runtime_err!("date_diff: unknown unit '{unit}'")),
            };
            Ok(Value::Int(result))
        }
        "date_part" => {
            let ts   = args.first().and_then(|v| v.as_int()).unwrap_or(0);
            let part = get_str(args, 1, "date_part")?;
            let (y, mo, d, h, mi, s) = utc_components(ts as u64);
            let day_of_week = ((ts / 86400 + 4) % 7) as u64; // 0=Mon .. 6=Sun (ISO)
            let result = match part.to_lowercase().as_str() {
                "year"    => y,
                "month"   => mo,
                "day"     => d,
                "hour"    => h,
                "minute"  => mi,
                "second"  => s,
                "weekday" => day_of_week,
                "unix"    => ts as u64,
                _ => return Err(runtime_err!("date_part: unknown part '{part}'")),
            };
            Ok(Value::Int(result as i64))
        }
        "format_date" => {
            let ts  = args.first().and_then(|v| v.as_int()).unwrap_or(0);
            let fmt = args.get(1).and_then(|v| v.as_str().map(str::to_string))
                         .unwrap_or_else(|| "%Y-%m-%d %H:%M:%S".to_string());
            let (y, mo, d, h, mi, s) = utc_components(ts as u64);
            Ok(Value::make_str(apply_date_format(&fmt, y, mo, d, h, mi, s)))
        }

        // ── Timezone ───────────────────────────────────────────────────────────
        "tz_offset" => {
            let tz = get_str(args, 0, "tz_offset")?;
            Ok(Value::Int(tz_offset_secs(&tz)))
        }
        "format_date_tz" => {
            let ts     = args.first().and_then(|v| v.as_int()).unwrap_or(0);
            let tz     = get_str(args, 1, "format_date_tz")?;
            let fmt    = args.get(2).and_then(|v| v.as_str().map(str::to_string))
                            .unwrap_or_else(|| "%Y-%m-%d %H:%M:%S".to_string());
            let offset = tz_offset_secs(&tz);
            let local_ts = (ts + offset).max(0) as u64;
            let (y, mo, d, h, mi, s) = utc_components(local_ts);
            let offset_h = offset / 3600;
            let offset_m = (offset.abs() % 3600) / 60;
            let tz_label = if offset == 0 {
                "UTC".to_string()
            } else if offset > 0 {
                format!("UTC+{offset_h}")
            } else {
                format!("UTC{offset_h}")
            };
            let _ = offset_m; // suppress warning — used in full RFC format below
            let formatted = apply_date_format(&fmt, y, mo, d, h, mi, s);
            Ok(Value::make_str(format!("{formatted} {tz_label}")))
        }
        "now_in_tz" => {
            use std::time::{SystemTime, UNIX_EPOCH};
            let tz     = get_str(args, 0, "now_in_tz")?;
            let fmt    = args.get(1).and_then(|v| v.as_str().map(str::to_string))
                            .unwrap_or_else(|| "%Y-%m-%d %H:%M:%S".to_string());
            let now_ts = SystemTime::now().duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64).unwrap_or(0);
            let offset   = tz_offset_secs(&tz);
            let local_ts = (now_ts + offset).max(0) as u64;
            let (y, mo, d, h, mi, s) = utc_components(local_ts);
            Ok(Value::make_str(apply_date_format(&fmt, y, mo, d, h, mi, s)))
        }

        // ── Telegram media (direct API calls via stored bot token) ─────────────
        "tg_send_photo" | "tg_send_document" | "tg_send_audio" | "tg_send_video" | "tg_send_animation" => {
            let kind = match name {
                "tg_send_document"  => "document",
                "tg_send_audio"     => "audio",
                "tg_send_video"     => "video",
                "tg_send_animation" => "animation",
                _                   => "photo",
            };
            let chat_id = args.first().and_then(|v| v.as_int())
                .ok_or_else(|| runtime_err!("{name}: first arg must be chat_id (int)"))?;
            let source  = get_str(args, 1, name)?;
            let caption = args.get(2).filter(|v| !matches!(v, Value::Null))
                             .map(|v| v.to_string());
            let token = shared.lock().await.bot_token.clone();
            let msg_id = tg_send_media_direct(&token, chat_id, kind, &source, caption.as_deref()).await?;
            Ok(Value::Int(msg_id))
        }
        "tg_forward" => {
            let to_chat   = args.first().and_then(|v| v.as_int())
                .ok_or_else(|| runtime_err!("tg_forward: arg 1 must be to_chat_id"))?;
            let from_chat = args.get(1).and_then(|v| v.as_int())
                .ok_or_else(|| runtime_err!("tg_forward: arg 2 must be from_chat_id"))?;
            let msg_id    = args.get(2).and_then(|v| v.as_int())
                .ok_or_else(|| runtime_err!("tg_forward: arg 3 must be message_id"))?;
            let token = shared.lock().await.bot_token.clone();
            tg_forward_direct(&token, to_chat, from_chat, msg_id).await?;
            Ok(Value::Null)
        }
        "tg_get_file_url" => {
            let file_id = get_str(args, 0, "tg_get_file_url")?;
            let token   = shared.lock().await.bot_token.clone();
            let file_path = tg_get_file_path(&token, &file_id).await?;
            Ok(Value::make_str(format!("https://api.telegram.org/file/bot{token}/{file_path}")))
        }
        "tg_download_file" => {
            use base64::{Engine as _, engine::general_purpose};
            let file_id   = get_str(args, 0, "tg_download_file")?;
            let token     = shared.lock().await.bot_token.clone();
            let file_path = tg_get_file_path(&token, &file_id).await?;
            let url       = format!("https://api.telegram.org/file/bot{token}/{file_path}");
            let bytes     = reqwest::get(&url).await
                .map_err(|e| runtime_err!("tg_download_file: {e}"))?
                .bytes().await
                .map_err(|e| runtime_err!("tg_download_file read: {e}"))?;
            Ok(Value::make_str(general_purpose::STANDARD.encode(&bytes)))
        }

        // Not a builtin
        _ => return Ok(None),
    };

    v.map(Some)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn get_str(args: &[Value], idx: usize, fn_name: &str) -> GravResult<String> {
    match args.get(idx) {
        Some(v) => Ok(v.to_string()),
        None    => Err(crate::runtime_err!("{fn_name}: missing string argument at position {idx}")),
    }
}

fn get_num(args: &[Value], idx: usize, fn_name: &str) -> GravResult<f64> {
    args.get(idx)
        .and_then(|v| v.as_float())
        .ok_or_else(|| crate::runtime_err!("{fn_name}: expected number at position {idx}"))
}

fn get_float(args: &[Value], idx: usize, fn_name: &str) -> GravResult<f64> {
    args.get(idx)
        .and_then(|v| v.as_float())
        .ok_or_else(|| crate::runtime_err!("{fn_name}: expected number at position {idx}"))
}

fn format_with_commas(n: i64) -> String {
    let s = n.abs().to_string();
    let with_commas: String = s.chars().rev().enumerate()
        .flat_map(|(i, c)| if i > 0 && i % 3 == 0 { vec![',', c] } else { vec![c] })
        .collect::<String>()
        .chars().rev().collect();
    if n < 0 { format!("-{with_commas}") } else { with_commas }
}

fn secs_to_date(secs: u64) -> String {
    // Naive UTC calculation without chrono
    let days_total = secs / 86400;
    let time_secs  = secs % 86400;
    let h = time_secs / 3600;
    let m = (time_secs % 3600) / 60;
    let s = time_secs % 60;
    // Gregorian calendar approximation
    let y400 = days_total / 146097;
    let rem   = days_total % 146097;
    let y100  = (rem / 36524).min(3);
    let rem   = rem - y100 * 36524;
    let y4    = rem / 1461;
    let rem   = rem % 1461;
    let y1    = (rem / 365).min(3);
    let year  = 1970 + y400 * 400 + y100 * 100 + y4 * 4 + y1;
    let day_of_year = rem - y1 * 365 + 1;
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let months = if leap {
        &[31u64, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        &[31u64, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut day = day_of_year;
    let mut month = 1u64;
    for (i, &dm) in months.iter().enumerate() {
        if day <= dm { month = i as u64 + 1; break; }
        day -= dm;
    }
    format!("{year}-{month:02}-{day:02} {h:02}:{m:02}:{s:02} UTC")
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON ↔ Value conversion helpers (pub for use in interpreter auto-load)
// ─────────────────────────────────────────────────────────────────────────────

pub fn json_to_value(jv: serde_json::Value) -> Value {
    match jv {
        serde_json::Value::Null        => Value::Null,
        serde_json::Value::Bool(b)     => Value::Bool(b),
        serde_json::Value::Number(n)   => {
            if let Some(i) = n.as_i64() { Value::Int(i) }
            else { Value::Float(n.as_f64().unwrap_or(0.0)) }
        }
        serde_json::Value::String(s)   => Value::make_str(s),
        serde_json::Value::Array(arr)  => {
            Value::make_list(arr.into_iter().map(json_to_value).collect())
        }
        serde_json::Value::Object(map) => {
            Value::make_map(map.into_iter().map(|(k, v)| (k, json_to_value(v))).collect())
        }
    }
}

pub fn value_to_json(v: &Value) -> serde_json::Value {
    match v {
        Value::Null        => serde_json::Value::Null,
        Value::Bool(b)     => serde_json::Value::Bool(*b),
        Value::Int(n)      => serde_json::json!(n),
        Value::Float(f)    => serde_json::json!(f),
        Value::Str(s)      => serde_json::Value::String(s.as_ref().clone()),
        Value::List(l)     => serde_json::Value::Array(
            l.borrow().iter().map(value_to_json).collect()
        ),
        Value::Map(m)      => serde_json::Value::Object(
            m.borrow().iter().map(|(k, v)| (k.clone(), value_to_json(v))).collect()
        ),
        Value::Fn(_) | Value::Ctx(_) => serde_json::Value::Null,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Date / time helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Decompose a Unix timestamp into UTC (year, month, day, hour, minute, second).
fn utc_components(secs: u64) -> (u64, u64, u64, u64, u64, u64) {
    let time_secs = secs % 86400;
    let h = time_secs / 3600;
    let m = (time_secs % 3600) / 60;
    let s = time_secs % 60;
    let days_total = secs / 86400;
    let y400 = days_total / 146097;
    let rem  = days_total % 146097;
    let y100 = (rem / 36524).min(3);
    let rem  = rem - y100 * 36524;
    let y4   = rem / 1461;
    let rem  = rem % 1461;
    let y1   = (rem / 365).min(3);
    let year = 1970 + y400 * 400 + y100 * 100 + y4 * 4 + y1;
    let doy  = rem - y1 * 365 + 1;
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let months: &[u64] = if leap { &[31,29,31,30,31,30,31,31,30,31,30,31] }
                         else     { &[31,28,31,30,31,30,31,31,30,31,30,31] };
    let mut day   = doy;
    let mut month = 1u64;
    for (i, &dm) in months.iter().enumerate() {
        if day <= dm { month = i as u64 + 1; break; }
        day -= dm;
    }
    (year, month, day, h, m, s)
}

/// Convert a Gregorian UTC date to a Unix timestamp.
fn gregorian_to_unix(year: u64, month: u8, day: u8, h: u8, mi: u8, s: u8) -> i64 {
    // Days from 1970-01-01 to the start of `year`
    let y = year as i64 - 1970;
    let leap_days = (y / 4) - (y / 100) + (y / 400) + 1; // leap years before 1970 correction
    let days_in_prev_years = y * 365 + {
        // actual leap years from 1970 to year-1
        let a = year as i64 - 1;
        (a / 4) - (a / 100) + (a / 400) - (1969/4 - 1969/100 + 1969/400)
    };
    let _ = leap_days; // suppress
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let months: &[i64] = if leap { &[0,31,60,91,121,152,182,213,244,274,305,335] }
                         else     { &[0,31,59,90,120,151,181,212,243,273,304,334] };
    let days = days_in_prev_years + months[(month as usize).saturating_sub(1)] + day as i64 - 1;
    days * 86400 + h as i64 * 3600 + mi as i64 * 60 + s as i64
}

/// Parse "YYYY-MM-DD" or "YYYY-MM-DD HH:MM:SS" (UTC) → Unix timestamp.
fn parse_date_str(s: &str) -> Option<i64> {
    let s = s.trim();
    // Try "YYYY-MM-DD HH:MM:SS"
    let parts: Vec<&str> = s.splitn(2, ' ').collect();
    let date_part = parts[0];
    let time_part = parts.get(1).copied().unwrap_or("00:00:00");
    let dp: Vec<u64> = date_part.split('-').filter_map(|x| x.parse().ok()).collect();
    let tp: Vec<u8>  = time_part.split(':').filter_map(|x| x.parse().ok()).collect();
    if dp.len() < 3 { return None; }
    let year  = dp[0];
    let month = dp[1] as u8;
    let day   = dp[2] as u8;
    let h     = tp.first().copied().unwrap_or(0);
    let mi    = tp.get(1).copied().unwrap_or(0);
    let sec   = tp.get(2).copied().unwrap_or(0);
    Some(gregorian_to_unix(year, month, day, h, mi, sec))
}

/// Apply a strftime-like format string to date components.
fn apply_date_format(fmt: &str, y: u64, mo: u64, d: u64, h: u64, mi: u64, s: u64) -> String {
    const MONTH_NAMES: &[&str] = &["","January","February","March","April","May","June",
        "July","August","September","October","November","December"];
    const DAY_NAMES:  &[&str] = &["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"];
    let mut out = String::with_capacity(fmt.len() + 10);
    let mut chars = fmt.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' { out.push(c); continue; }
        match chars.next() {
            Some('Y') => out.push_str(&format!("{y:04}")),
            Some('y') => out.push_str(&format!("{:02}", y % 100)),
            Some('m') => out.push_str(&format!("{mo:02}")),
            Some('d') => out.push_str(&format!("{d:02}")),
            Some('H') => out.push_str(&format!("{h:02}")),
            Some('M') => out.push_str(&format!("{mi:02}")),
            Some('S') => out.push_str(&format!("{s:02}")),
            Some('B') => out.push_str(MONTH_NAMES.get(mo as usize).copied().unwrap_or("")),
            Some('b') | Some('h') => out.push_str(&MONTH_NAMES.get(mo as usize).copied().unwrap_or("")[..3]),
            Some('A') => { /* weekday name — approximate */
                let days_since_epoch = gregorian_to_unix(y, mo as u8, d as u8, 0, 0, 0) / 86400;
                out.push_str(DAY_NAMES[((days_since_epoch + 3).rem_euclid(7)) as usize]);
            }
            Some('a') => {
                let days_since_epoch = gregorian_to_unix(y, mo as u8, d as u8, 0, 0, 0) / 86400;
                out.push_str(&DAY_NAMES[((days_since_epoch + 3).rem_euclid(7)) as usize][..3]);
            }
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('%') => out.push('%'),
            Some(other) => { out.push('%'); out.push(other); }
            None => out.push('%'),
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Timezone offset table  (standard offsets — no DST)
// ─────────────────────────────────────────────────────────────────────────────

fn tz_offset_secs(tz: &str) -> i64 {
    let tz = tz.trim();
    // Numeric offset:  "+3", "+05:30", "-5:00", "UTC+3", "GMT-5"
    let norm = tz.trim_start_matches("UTC").trim_start_matches("GMT");
    if let Some(stripped) = norm.strip_prefix('+').or_else(|| if norm.starts_with('-') { Some(norm) } else { None }) {
        let sign: i64 = if norm.starts_with('-') { -1 } else { 1 };
        let body = stripped.trim_start_matches('-').trim_start_matches('+');
        let parts: Vec<&str> = body.split(':').collect();
        if let Ok(h) = parts[0].parse::<i64>() {
            let m = parts.get(1).and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
            return sign * (h * 3600 + m * 60);
        }
    }
    // Named zones (standard time, no DST)
    match tz {
        "UTC" | "GMT" | "Z"                                   =>  0,
        "Europe/London"  | "WET"                               =>  0,
        "Europe/Paris"   | "Europe/Berlin"  | "Europe/Rome"   |
        "Europe/Madrid"  | "Europe/Warsaw"  | "Europe/Prague" |
        "Europe/Vienna"  | "CET"                               =>  3_600,
        "Europe/Athens"  | "Europe/Helsinki"| "Europe/Kyiv"   |
        "Europe/Bucharest"| "EET"                              =>  7_200,
        "Europe/Moscow"  | "Europe/Istanbul"| "Europe/Minsk"  =>  10_800,
        "Asia/Dubai"     | "Asia/Muscat"                       =>  14_400,
        "Asia/Karachi"   | "Asia/Tashkent"                     =>  18_000,
        "Asia/Kolkata"   | "Asia/Colombo"                      =>  19_800,
        "Asia/Dhaka"     | "Asia/Almaty"                       =>  21_600,
        "Asia/Bangkok"   | "Asia/Jakarta"   | "Asia/Saigon"   =>  25_200,
        "Asia/Shanghai"  | "Asia/Singapore" | "Asia/Taipei"   |
        "Asia/Hong_Kong" | "CST"                               =>  28_800,
        "Asia/Tokyo"     | "Asia/Seoul"     | "JST"            =>  32_400,
        "Australia/Sydney" | "Australia/Melbourne"             =>  36_000,
        "Pacific/Auckland"                                     =>  43_200,
        "Atlantic/Azores"                                      => -3_600,
        "America/Noronha"                                      => -7_200,
        "America/Sao_Paulo"| "America/Buenos_Aires"            => -10_800,
        "America/Halifax"                                      => -14_400,
        "America/New_York" | "America/Detroit" | "EST"         => -18_000,
        "America/Chicago"  | "America/Winnipeg"| "CST-US"     => -21_600,
        "America/Denver"   | "America/Phoenix" | "MST"         => -25_200,
        "America/Los_Angeles" | "America/Vancouver" | "PST"   => -28_800,
        "America/Anchorage"                                    => -32_400,
        "Pacific/Honolulu" | "HST"                             => -36_000,
        _                                                       =>  0, // unknown → UTC
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Telegram API helpers for stdlib media functions
// ─────────────────────────────────────────────────────────────────────────────

async fn tg_api_post(token: &str, method: &str, body: serde_json::Value) -> GravResult<serde_json::Value> {
    let url = format!("https://api.telegram.org/bot{token}/{method}");
    let resp = reqwest::Client::new()
        .post(&url).json(&body).send().await
        .map_err(|e| crate::runtime_err!("{method}: {e}"))?
        .json::<serde_json::Value>().await
        .map_err(|e| crate::runtime_err!("{method} read: {e}"))?;
    if !resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
        let desc = resp.get("description").and_then(|v| v.as_str()).unwrap_or("Telegram error");
        return Err(crate::runtime_err!("{method}: {desc}"));
    }
    Ok(resp.get("result").cloned().unwrap_or(serde_json::Value::Null))
}

async fn tg_send_media_direct(
    token:   &str,
    chat_id: i64,
    kind:    &str,
    source:  &str,
    caption: Option<&str>,
) -> GravResult<i64> {
    let media_key = match kind {
        "document" => "document", "audio" => "audio",
        "video"    => "video",    "animation" => "animation",
        _          => "photo",
    };
    let api_method = match kind {
        "document" => "sendDocument", "audio" => "sendAudio",
        "video"    => "sendVideo",    "animation" => "sendAnimation",
        _          => "sendPhoto",
    };
    let mut params = serde_json::json!({ "chat_id": chat_id, media_key: source });
    if let Some(cap) = caption { params["caption"] = serde_json::json!(cap); }
    let result = tg_api_post(token, api_method, params).await?;
    Ok(result.get("message_id").and_then(|v| v.as_i64()).unwrap_or(0))
}

async fn tg_forward_direct(token: &str, to_chat: i64, from_chat: i64, msg_id: i64) -> GravResult<()> {
    let params = serde_json::json!({ "chat_id": to_chat, "from_chat_id": from_chat, "message_id": msg_id });
    tg_api_post(token, "forwardMessage", params).await?;
    Ok(())
}

async fn tg_get_file_path(token: &str, file_id: &str) -> GravResult<String> {
    let params = serde_json::json!({ "file_id": file_id });
    let result = tg_api_post(token, "getFile", params).await?;
    result.get("file_path")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| crate::runtime_err!("tg_get_file: no file_path in response"))
}
