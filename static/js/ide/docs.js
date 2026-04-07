// ── Docs ──────────────────────────────────────────────────────
function ideToggleDocs() {
    IDE.docsVisible = !IDE.docsVisible;
    document.getElementById('ide-docs-panel').classList.toggle('open',   IDE.docsVisible);
    document.getElementById('ide-docs-overlay').classList.toggle('open', IDE.docsVisible);
}

function ideDocsSearch(q) {
    document.querySelectorAll('.ide-docs-section').forEach(s => {
        s.style.display = !q || s.textContent.toLowerCase().includes(q.toLowerCase()) ? '' : 'none';
    });
}

function ideRenderDocs() {
    const el = document.getElementById('ide-docs-content');
    if (!el) return;
    el.innerHTML = DOCS_HTML;
}


// ── Docs HTML ─────────────────────────────────────────────────
const DOCS_HTML = `
<div class="ide-docs-section">
  <div class="ide-docs-h1">Gravitix Language Reference</div>
  <div class="ide-docs-p">A high-performance scripting language for building bots. 96 features. Rust backend.</div>
</div>

<!-- ═══════════════ BASICS ═══════════════ -->

<div class="ide-docs-section">
  <div class="ide-docs-h2">Variables &amp; Types</div>
  <pre class="ide-docs-code">let x = 42                  // type inferred
let name: str = "Alice"     // explicit type
let pi: float = 3.14
let active = true
let items = [1, 2, 3]
let config = { key: "value" }

// Types: int, float, bool, str, list, map, void, any

// Type checking
type_of(42)           // "int"
is_int(x)             // true
is_null(val)          // true/false

// Conversion
int("42")   float("3.14")   str(42)   bool(1)</pre>
</div>

<div class="ide-docs-section">
  <div class="ide-docs-h2">Functions</div>
  <pre class="ide-docs-code">fn greet(name: str) -> str {
    return "Hello, " + name + "!"
}

// Default params
fn power(base: int, exp: int = 2) -> int {
    return base ** exp
}

let sq = power(5)       // 25
let cb = power(5, 3)    // 125

// Doc comments (generate with: gravitix doc file.grav)
/// Greets a user by name.
/// @param name - display name
fn greet(name: str) -> str { ... }</pre>
</div>

<!-- ═══════════════ HANDLERS ═══════════════ -->

<div class="ide-docs-section">
  <div class="ide-docs-h2">Handlers &amp; Triggers</div>
  <pre class="ide-docs-code">// Commands
on /start { emit "Welcome!" }
on /help  { emit "Commands: /start, /help" }

// Any text message
on msg { emit "You said: {ctx.text}" }

// With guard
on /admin guard ctx.user_id == 12345 {
    emit "Admin only"
}

// Callbacks (inline buttons)
on callback "yes" { emit "Confirmed!" }

// Media
on file  { emit "File: {ctx.file_url}" }
on image { emit "Photo received!" }
on voice { emit "Voice: {ctx.duration}s" }

// User events
on join  { emit "Welcome!" }
on leave { emit "Goodbye!" }

// More triggers
on reaction "👍"  { emit "Thanks!" }
on mention        { emit "You called?" }
on dm             { emit "This is a DM" }
on edited         { emit "Edited" }
on forward        { emit "Forwarded" }
on thread         { emit "Thread reply" }
on poll_vote      { emit "Voted: {ctx.vote_option}" }
on idle 300000    { emit "Still there?" }
on any            { log("catch-all") }
on error          { emit "Error occurred" }</pre>
</div>

<div class="ide-docs-section">
  <div class="ide-docs-h2">Context (ctx)</div>
  <pre class="ide-docs-code">ctx.user_id        // int - sender ID
ctx.username       // str - sender name
ctx.room_id        // int - room ID
ctx.text           // str? - message text
ctx.message_id     // int - message ID
ctx.command        // str? - command without /
ctx.args           // list - command arguments
ctx.callback_data  // str? - button data
ctx.timestamp      // int - unix time
ctx.is_dm          // bool
ctx.platform       // str - "vortex"/"telegram"
ctx.intent         // str? - NLU intent
ctx.file_url       // str? - uploaded file
ctx.reaction       // str? - emoji
ctx.user_lang      // str? - language code</pre>
</div>

<!-- ═══════════════ STATE ═══════════════ -->

<div class="ide-docs-section">
  <div class="ide-docs-h2">State</div>
  <pre class="ide-docs-code">state {
    count: int = 0
    users: map&lt;int, str&gt; = {}
    active: bool = true
}

state.count += 1
state.users[ctx.user_id] = ctx.username

// Scoped state
state {
    score: int = 0 per user
    topic: str = "" per room
}</pre>
</div>

<!-- ═══════════════ CONTROL FLOW ═══════════════ -->

<div class="ide-docs-section">
  <div class="ide-docs-h2">Control Flow</div>
  <pre class="ide-docs-code">// If / elif / else
if x > 0 {
    emit "positive"
} elif x == 0 {
    emit "zero"
} else {
    emit "negative"
}

// While
while i &lt; 10 { i += 1 }

// For-in
for item in [1, 2, 3] { emit "{item}" }
for key in config.keys() { emit "{key}" }

// Break, Continue, Return
for i in range(0, 100) {
    if i % 2 == 0 { continue }
    if i > 50 { break }
}</pre>
</div>

<div class="ide-docs-section">
  <div class="ide-docs-h2">Pattern Matching</div>
  <pre class="ide-docs-code">match ctx.text {
    "hello"       =&gt; emit "Hi!"
    /^calc (.+)/  =&gt; emit "Calculating..."
    42            =&gt; emit "The answer!"
    1..10         =&gt; emit "Single digit"
    _             =&gt; emit "Unknown"
}

// Enum destructuring
match status {
    Ok(value)  =&gt; emit "Got: {value}"
    Err(msg)   =&gt; emit "Error: {msg}"
}

// Struct patterns
match point {
    Point { x: 0, y } =&gt; emit "Y axis"
    _                  =&gt; emit "Other"
}</pre>
</div>

<!-- ═══════════════ STRINGS & COLLECTIONS ═══════════════ -->

<div class="ide-docs-section">
  <div class="ide-docs-h2">Strings</div>
  <pre class="ide-docs-code">// Interpolation
let msg = "Hello, {ctx.username}!"

// Multi-line
let text = """
    Multi-line
    string
"""

// Operations
len("hello")                // 5
contains("hello", "ell")    // true
replace("hello", "l", "r")  // "herro"
split("a,b,c", ",")         // ["a", "b", "c"]
join(["a", "b"], ", ")       // "a, b"
trim("  hi  ")               // "hi"
lowercase("Hello")           // "hello"
uppercase("Hello")           // "HELLO"
fmt("Hi {name}", { name: "Bob" })  // "Hi Bob"</pre>
</div>

<div class="ide-docs-section">
  <div class="ide-docs-h2">Collections</div>
  <pre class="ide-docs-code">// Lists
let items = [1, 2, 3, 4, 5]
items[0]          // 1
items[-1]         // 5 (last)
items[1..3]       // [2, 3] (slice)

// Chain methods
items.map(fn(x) { x * 2 })
items.filter(fn(x) { x > 3 })
items.sort()
items.reverse()
items.find(fn(x) { x == 3 })
items.reduce(fn(a, b) { a + b }, 0)
items.any(fn(x) { x > 4 })
items.all(fn(x) { x > 0 })
items.enumerate()
items.flat_map(fn(x) { [x, x * 10] })

push(items, 6)
pop(items)

// Maps
let cfg = { name: "Bot", version: 1 }
cfg.name           // "Bot"
cfg["version"]     // 1
cfg.has("name")    // true
cfg.keys()         // ["name", "version"]

// List comprehension
let squares = [x ** 2 for x in range(1, 11)]
let evens = [x for x in range(1, 20) if x % 2 == 0]</pre>
</div>

<!-- ═══════════════ FLOWS ═══════════════ -->

<div class="ide-docs-section">
  <div class="ide-docs-h2">Flows (Dialogues)</div>
  <pre class="ide-docs-code">flow register {
    emit "What is your name?"
    let name = wait msg       // suspend until reply

    emit "How old are you?"
    let age = wait msg

    state.users[ctx.user_id] = name
    emit "Registered: {name}, age {age}"
}

on /register { run flow register }

// Wait for button press
flow confirm {
    keyboard "Sure?" [["Yes", "yes"], ["No", "no"]]
    let answer = wait callback
    if answer == "yes" { emit "Done!" }
}</pre>
</div>

<!-- ═══════════════ PIPE & ERRORS ═══════════════ -->

<div class="ide-docs-section">
  <div class="ide-docs-h2">Pipe Operator |&gt;</div>
  <pre class="ide-docs-code">let clean = text |&gt; trim |&gt; lowercase
let words = text |&gt; split(" ") |&gt; reverse

// With error propagation (?)
let data = input |&gt; parse_json? |&gt; validate? |&gt; save</pre>
</div>

<div class="ide-docs-section">
  <div class="ide-docs-h2">Error Handling</div>
  <pre class="ide-docs-code">// Try / Catch / Finally
try {
    let data = http_get(url)
    emit data.body
} catch e {
    emit "Error: {e.message}"
} finally {
    track("attempt")
}

// Result type + ? operator
fn divide(a: int, b: int) -&gt; Result {
    if b == 0 { return Err("division by zero") }
    return Ok(a / b)
}
let r = divide(10, 3)?

// Assert
assert len(items) > 0, "must not be empty"</pre>
</div>

<!-- ═══════════════ KEYBOARDS & RICH ═══════════════ -->

<div class="ide-docs-section">
  <div class="ide-docs-h2">Keyboards &amp; Rich Messages</div>
  <pre class="ide-docs-code">// Inline keyboard
keyboard "Choose:" [
    ["Option A", "opt_a"],
    ["Option B", "opt_b"]
]

// Rich message
emit rich {
    title: "Product"
    text: "Premium — $9.99/mo"
    image: "https://example.com/img.png"
    buttons: [["Buy", "buy"], ["Later", "skip"]]
}

// Edit / Delete / Reply
edit msg_id { text: "Updated" }
delete ctx.message_id
reply ctx.message_id { text: "Reply" }</pre>
</div>

<!-- ═══════════════ STRUCTS & ENUMS ═══════════════ -->

<div class="ide-docs-section">
  <div class="ide-docs-h2">Structs &amp; Enums</div>
  <pre class="ide-docs-code">struct User {
    name: str
    age: int
    active: bool = true
}

impl User {
    fn greet(self) -&gt; str {
        return "Hi, I'm {self.name}!"
    }
}

let u = User { name: "Alice", age: 25 }
emit u.greet()

// Enums
enum Status { Pending, Active, Banned(str) }

let s = Status::Banned("spam")
match s {
    Status::Banned(r) =&gt; emit "Banned: {r}"
    _ =&gt; emit "OK"
}</pre>
</div>

<div class="ide-docs-section">
  <div class="ide-docs-h2">Lambdas &amp; Destructuring</div>
  <pre class="ide-docs-code">// Lambda
let double = fn(x) { x * 2 }
items.map(fn(x) { x + 1 })

// Map destructuring
let { name, age } = user_data

// List destructuring
let [first, second, ...rest] = items

// Optional chaining
let city = user?.address?.city
let name = user?.name ?? "Anonymous"</pre>
</div>

<!-- ═══════════════ SCHEDULERS ═══════════════ -->

<div class="ide-docs-section">
  <div class="ide-docs-h2">Schedulers</div>
  <pre class="ide-docs-code">every 5s { emit "ping" }
every 1 hour { emit "check" }
every 24 hours { emit broadcast "daily" }

at "09:00" { emit "Good morning!" }

schedule "0 9 * * 1-5" { emit "Weekday 9AM" }

// Human-readable
every monday at 9:00 { emit "Standup!" }
every weekday at 18:00 { emit "EOD" }
every 1st of month at 10:00 { emit "Monthly" }</pre>
</div>

<!-- ═══════════════ FSM ═══════════════ -->

<div class="ide-docs-section">
  <div class="ide-docs-h2">FSM (State Machines)</div>
  <pre class="ide-docs-code">fsm order_flow {
    state idle {
        on /order =&gt; selecting
    }
    state selecting {
        on msg {
            state.item = ctx.text
            emit "Confirm {ctx.text}?"
            =&gt; confirming
        }
    }
    state confirming {
        on callback "yes" { emit "Ordered!"; =&gt; idle }
        on callback "no"  { emit "Cancelled"; =&gt; idle }
    }
}
on /order { run fsm order_flow }</pre>
</div>

<!-- ═══════════════ PERMISSIONS & RATE LIMIT ═══════════════ -->

<div class="ide-docs-section">
  <div class="ide-docs-h2">Permissions (RBAC)</div>
  <pre class="ide-docs-code">permissions {
    roles: {
        admin: ["*"]
        moderator: ["ban", "mute", "delete_msg"]
        user: ["send_msg", "upload_file"]
    }
    default: "user"
}

on /ban require permission "ban" { emit "Banned" }

assign_role(user_id, "moderator")
check_permission(user_id, "ban")  // true</pre>
</div>

<div class="ide-docs-section">
  <div class="ide-docs-h2">Rate Limiting</div>
  <pre class="ide-docs-code">ratelimit {
    global: 100 per minute
    per_user: 20 per minute
    command "/ai": 5 per minute
}

on /search ratelimit 5 per user per 60s { ... }</pre>
</div>

<!-- ═══════════════ DECORATORS & EVENTS ═══════════════ -->

<div class="ide-docs-section">
  <div class="ide-docs-h2">Decorators</div>
  <pre class="ide-docs-code">@retry(3)
@logged
fn fetch_data(url: str) -&gt; str {
    return http_get(url).body
}

@cached(300)
fn expensive_query(q: str) { ... }

// Available: @retry(n), @logged, @cached(ttl)</pre>
</div>

<div class="ide-docs-section">
  <div class="ide-docs-h2">Events</div>
  <pre class="ide-docs-code">// Fire custom events
on /buy {
    fire "order_placed" { user: ctx.user_id, item: ctx.args[0] }
}

// Handle custom events
on event "order_placed" {
    emit "Order from {ctx.event_data.user}!"
    notify(ctx.event_data.user, "Order confirmed!")
}

// Reactive state watching
watch state.user_count {
    if state.user_count % 100 == 0 {
        emit broadcast "Milestone: {state.user_count} users!"
    }
}</pre>
</div>

<!-- ═══════════════ TESTING ═══════════════ -->

<div class="ide-docs-section">
  <div class="ide-docs-h2">Testing</div>
  <pre class="ide-docs-code">test "math" {
    assert 2 + 2 == 4
    assert len("hello") == 5
}

test "with mocks" {
    mock http_get { return { status: 200, body: "ok" } }
    let r = fetch_data("url")
    expect(r).to_equal("ok")
    expect(r).to_not_be_null()
    expect(fn() { panic("x") }).to_throw()
}

test scenario "order flow" {
    simulate user(123) sends "/start"
    expect_reply contains "Welcome"
    simulate user(123) clicks "confirm"
    expect_reply contains "Done"
}

// Run: gravitix test bot.grav</pre>
</div>

<!-- ═══════════════ VALIDATION & MEMORY ═══════════════ -->

<div class="ide-docs-section">
  <div class="ide-docs-h2">Validation</div>
  <pre class="ide-docs-code">validate ctx.args[0] as email or { emit "Bad email"; stop }
validate ctx.args[1] as phone or { emit "Bad phone"; stop }
validate ctx.args[2] as int range(18, 120) or { emit "Bad age"; stop }

// Types: email, phone, url, int, float, len(min, max)</pre>
</div>

<div class="ide-docs-section">
  <div class="ide-docs-h2">Bot Memory</div>
  <pre class="ide-docs-code">// Per-user key-value memory (persists across sessions)
remember(ctx.user_id, "last_topic", ctx.text)
let prev = recall(ctx.user_id, "last_topic")
forget(ctx.user_id, "last_topic")
let mems = memories(ctx.user_id)</pre>
</div>

<!-- ═══════════════ DATABASE ═══════════════ -->

<div class="ide-docs-section">
  <div class="ide-docs-h2">Database</div>
  <pre class="ide-docs-code">// Key-value
db.set("users:123", { name: "Alice", score: 100 })
let user = db.get("users:123")
db.del("users:123")

// Query builder
let results = db.find("users")
    .where({ score: { gt: 50 } })
    .sort("score")
    .limit(10)
    .exec()

// Audit trail
audit("user_banned", { user_id: 123, reason: "spam" })</pre>
</div>

<!-- ═══════════════ HTTP & AI ═══════════════ -->

<div class="ide-docs-section">
  <div class="ide-docs-h2">HTTP &amp; AI</div>
  <pre class="ide-docs-code">// HTTP
let res = http_get("https://api.example.com/data")
let res = http_post(url, { key: "value" })

// AI
let answer = ai("Explain quantum computing")
let resp = ai_chat([
    { role: "system", content: "You are helpful." },
    { role: "user", content: ctx.text }
])</pre>
</div>

<!-- ═══════════════ WEBHOOKS & FORMS ═══════════════ -->

<div class="ide-docs-section">
  <div class="ide-docs-h2">Webhooks</div>
  <pre class="ide-docs-code">webhook "/github" {
    secret: env("GITHUB_SECRET")
    on "push" {
        emit broadcast "Push to {ctx.webhook_body.repo}"
    }
}
// URL: POST /api/bot/webhook/{bot_id}/github</pre>
</div>

<div class="ide-docs-section">
  <div class="ide-docs-h2">Forms</div>
  <pre class="ide-docs-code">let data = form {
    field "name" type text required
    field "rating" type rating(1, 5)
    field "comment" type textarea
    field "category" type select ["bug", "feature"]
    submit "Send"
}
// Types: text, textarea, number, email, phone, rating, select</pre>
</div>

<!-- ═══════════════ TABLES, CHARTS, STREAMS ═══════════════ -->

<div class="ide-docs-section">
  <div class="ide-docs-h2">Tables &amp; Charts</div>
  <pre class="ide-docs-code">// Table
table {
    source: db.find("users").exec()
    columns: ["name", "email", "score"]
    page_size: 10
}

// Chart (ASCII)
chart {
    type: "bar"
    title: "Commands/day"
    data: [45, 62, 38, 71]
    labels: ["Mon", "Tue", "Wed", "Thu"]
}</pre>
</div>

<div class="ide-docs-section">
  <div class="ide-docs-h2">Streaming</div>
  <pre class="ide-docs-code">stream {
    emit "Thinking..."
    let answer = ai(ctx.text)
    emit answer
}</pre>
</div>

<!-- ═══════════════ MODULES & MIDDLEWARE ═══════════════ -->

<div class="ide-docs-section">
  <div class="ide-docs-h2">Modules &amp; Imports</div>
  <pre class="ide-docs-code">// utils.grav
fn capitalize(s: str) -&gt; str { ... }

// main.grav
import "utils.grav"
import "handlers/admin.grav"</pre>
</div>

<div class="ide-docs-section">
  <div class="ide-docs-h2">Middleware &amp; Hooks</div>
  <pre class="ide-docs-code">middleware logging(ctx, next) {
    log("-&gt; " + ctx.command)
    let result = next(ctx)
    log("&lt;- done")
    return result
}
use middleware logging

// Simple hooks
hook before { log("before: {ctx.command}") }
hook after  { track("executed", { cmd: ctx.command }) }</pre>
</div>

<!-- ═══════════════ ADVANCED ═══════════════ -->

<div class="ide-docs-section">
  <div class="ide-docs-h2">Advanced Features</div>
  <pre class="ide-docs-code">// Circuit breaker
circuit_breaker "api" { threshold: 5, timeout: 30000 }
let data = with_breaker "api" { http_get(url) }

// Channels (actor model)
let ch = channel("orders")
spawn { for msg in ch { process(msg) } }
ch.send({ id: uuid() })

// Queues
queue "emails" { http_post(mail_api, ctx.data) }
enqueue "emails" { to: "user@mail.com" }

// Sandbox
let r = sandbox { timeout: 5000, deny: ["http"], code: src }

// Caching
let data = cache "weather" ttl 300 { http_get(weather_url) }

// A/B testing
abtest "welcome" {
    variant "short" weight 50 { emit "Hi!" }
    variant "long" weight 50 { emit "Welcome to..." }
}

// Spawn background task
spawn { long_running_task() }

// Defer (cleanup)
defer { db.del("temp:" + id) }

// Parallel execution
let [a, b] = parallel [fetch(url1), fetch(url2)]</pre>
</div>

<!-- ═══════════════ NLU ═══════════════ -->

<div class="ide-docs-section">
  <div class="ide-docs-h2">NLU (Intents &amp; Entities)</div>
  <pre class="ide-docs-code">intents {
    greeting: ["hi", "hello", "hey"]
    farewell: ["bye", "goodbye"]
    order: ["buy", "order", "purchase"]
}
on intent "greeting" { emit "Hello!" }
on intent "order" { run flow order_wizard }
on intent unknown { emit ai(ctx.text) }

entities {
    email: builtin
    phone: builtin
    city: ["Moscow", "London", "Tokyo"]
}
let found = extract(ctx.text)
// found.email, found.phone, found.city</pre>
</div>

<!-- ═══════════════ i18n & MULTIPLATFORM ═══════════════ -->

<div class="ide-docs-section">
  <div class="ide-docs-h2">i18n &amp; Multiplatform</div>
  <pre class="ide-docs-code">// Internationalization
lang "en" { welcome: "Welcome!", help: "Commands: /start" }
lang "ru" { welcome: "Добро пожаловать!", help: "Команды: /start" }
emit i18n("welcome")  // auto-detects language

// Multiplatform
multiplatform {
    vortex: { url: env("VORTEX_URL"), token: env("VORTEX_TOKEN") }
    telegram: { token: env("TG_TOKEN") }
}
if ctx.platform == "telegram" { ... }</pre>
</div>

<!-- ═══════════════ MISC ═══════════════ -->

<div class="ide-docs-section">
  <div class="ide-docs-h2">Migrations &amp; Admin</div>
  <pre class="ide-docs-code">// Run-once data migration
migration "v2_add_scores" {
    for user in db.find("users").exec() {
        if user.score == null {
            db.set("users:" + user.id, { ...user, score: 0 })
        }
    }
}

// Auto-generated admin panel
admin {
    title: "MyBot Admin"
    section "Users" {
        table: db.find("users").exec()
        actions: ["ban", "delete"]
    }
}

// Type aliases
typedef Email = str where validate(it, "email")
typedef Age = int where it &gt;= 0 and it &lt;= 150

// Metrics
metrics { counter commands_total, histogram response_time }</pre>
</div>

<div class="ide-docs-section">
  <div class="ide-docs-h2">Debugging</div>
  <pre class="ide-docs-code">log("debug: {value}")
print("console output")
breakpoint           // pause in REPL/test
debug { result }     // log value + line number</pre>
</div>

<!-- ═══════════════ BUILTINS ═══════════════ -->

<div class="ide-docs-section">
  <div class="ide-docs-h2">Built-in Functions</div>
  <pre class="ide-docs-code">// String
len(s)  trim(s)  lowercase(s)  uppercase(s)
contains(s, sub)  replace(s, from, to)
split(s, sep)  join(list, sep)  sanitize(s)
fmt(template, data)

// Math
abs(n)  min(a,b)  max(a,b)  floor(f)  ceil(f)
round(f)  sqrt(f)  pow(a,b)  random()

// Collections
range(a, b)  push(list, val)  pop(list)  reverse(list)

// Conversion
int(x)  float(x)  str(x)  bool(x)  type_of(x)

// Type check
is_null(x) is_int(x) is_float(x) is_str(x) is_list(x) is_map(x)

// Time
now_unix()  now_str()  sleep(ms)

// HTTP
http_get(url)  http_post(url, body)
http_put(url, body)  http_delete(url)

// AI
ai(prompt)  ai_chat(messages)

// JSON
json_parse(str)  json_stringify(val)

// Regex
regex_match(text, pat)  regex_find_all(text, pat)
regex_replace(text, pat, repl)

// Crypto
encrypt(text, key)  decrypt(cipher, key)  uuid()

// Bot
notify(user_id, text)  notify_room(room_id, text)
remember(uid, key, val)  recall(uid, key)
assign_role(uid, role)  check_permission(uid, perm)
extract(text)  track(event, data)
audit(action, details)</pre>
</div>

<!-- ═══════════════ CLI ═══════════════ -->

<div class="ide-docs-section">
  <div class="ide-docs-h2">CLI Commands</div>
  <pre class="ide-docs-code">gravitix run bot.grav --token TOKEN --url URL
gravitix check bot.grav     # syntax check
gravitix fmt bot.grav       # format code
gravitix test bot.grav      # run tests
gravitix repl [bot.grav]    # interactive REPL
gravitix doc bot.grav       # generate docs
gravitix install package    # install plugin</pre>
</div>`;
