/* ============================================================
   Gravitix Language Reference — full-screen documentation
   ============================================================ */
'use strict';

/* ── TOC definition ──────────────────────────────────────── */
const GX_TOC = [
  { id: 'intro',        label: 'Introduction',           icon: '📖' },
  { id: 'quickstart',   label: 'Quick Start',             icon: '🚀' },
  { id: 'syntax',       label: 'Syntax at a Glance',      icon: '🗺️' },
  { group: 'Fundamentals' },
  { id: 'variables',    label: 'Variables',               icon: '📦' },
  { id: 'types',        label: 'Types',                   icon: '🔢' },
  { id: 'operators',    label: 'Operators',               icon: '⚙️' },
  { id: 'strings',      label: 'Strings',                 icon: '🔤' },
  { group: 'Control Flow' },
  { id: 'if',           label: 'if / elif / else',        icon: '🔀' },
  { id: 'loops',        label: 'Loops',                   icon: '🔁' },
  { id: 'match',        label: 'match Expression',        icon: '🎯' },
  { group: 'Functions & Scope' },
  { id: 'functions',    label: 'Functions',               icon: '🧮' },
  { group: 'Event System' },
  { id: 'handlers',     label: 'Event Handlers',          icon: '📡' },
  { id: 'guard',        label: 'Guard Clauses',           icon: '🛡️' },
  { id: 'ctx',          label: 'Context Object',          icon: '🌐' },
  { group: 'State & Conversations' },
  { id: 'state',        label: 'State Management',        icon: '💾' },
  { id: 'flows',        label: 'Flows',                   icon: '🌊' },
  { group: 'I/O & Scheduling' },
  { id: 'emit',         label: 'Emit & Messages',         icon: '📤' },
  { id: 'schedule',     label: 'Scheduling',              icon: '⏰' },
  { id: 'pipe',         label: 'Pipe Operator  |>',       icon: '↪' },
  { group: 'Advanced Language' },
  { id: 'complex_type', label: 'Complex Numbers',         icon: '🔬' },
  { id: 'bitwise',      label: 'Bitwise Operators',       icon: '⚡' },
  { id: 'error',        label: 'Error Handling',          icon: '🛡️' },
  { id: 'structs',      label: 'Structs & Enums',         icon: '🏗️' },
  { group: 'Mathematics' },
  { id: 'math_core',    label: 'Core Math',               icon: '📐' },
  { id: 'math_complex', label: 'Complex Analysis',        icon: '🌀' },
  { id: 'math_calculus',label: 'Calculus',                icon: '∫' },
  { id: 'math_linalg',  label: 'Linear Algebra',          icon: '🧮' },
  { id: 'math_numth',   label: 'Number Theory',           icon: '🔢' },
  { id: 'math_stats',   label: 'Statistics',              icon: '📊' },
  { id: 'math_special', label: 'Special Functions',       icon: '🎩' },
  { id: 'math_transforms', label: 'Transforms & FFT',     icon: '〰️' },
  { group: 'Reference' },
  { id: 'builtins',     label: 'Built-in Functions',      icon: '📚' },
  { id: 'examples',     label: 'Complete Examples',       icon: '💡' },
  { id: 'bestpractices',label: 'Best Practices',          icon: '✅' },
];

/* ── Docs content ────────────────────────────────────────── */
const GX_SECTIONS = {

/* ─── INTRO ─────────────────────────────────────────────── */
intro: `
<h1>Gravitix Language Reference</h1>
<p class="gxd-lead">A concise, safe, and expressive scripting language for building Vortex bots — no boilerplate, just logic.</p>

<div class="gxd-badge-row">
  <span class="gxd-badge gxd-badge-purple">v1.0</span>
  <span class="gxd-badge gxd-badge-blue">Turing-Complete</span>
  <span class="gxd-badge gxd-badge-green">Rust-inspired</span>
</div>

<h2>What is Gravitix?</h2>
<p>Gravitix is a domain-specific language (DSL) designed from the ground up for writing Vortex bots. Where other languages require libraries, callbacks, and boilerplate, Gravitix gives you first-class event handlers, conversation flows, and built-in state — all in a clean, readable syntax inspired by Rust.</p>

<div class="gxd-callout gxd-callout-blue">
  <div class="gxd-callout-title">📌 Design goals</div>
  <ul>
    <li><strong>Readable</strong> — code reads like intent, not machinery</li>
    <li><strong>Safe</strong> — static types catch errors before runtime</li>
    <li><strong>Expressive</strong> — flows, guards, and pattern matching are built-in</li>
    <li><strong>Minimal</strong> — no classes, no inheritance, no frameworks to learn</li>
  </ul>
</div>

<h2>Who is this for?</h2>
<p>Gravitix is for anyone who wants to build a Vortex bot quickly — whether you have never written code before, or you are a seasoned developer who is tired of Python boilerplate. This reference teaches Gravitix from first principles: no prior experience required.</p>

<h2>How to read this reference</h2>
<p>Each section builds on the previous ones. If you are new to programming, read from top to bottom. If you already know another language, use the table of contents to jump directly to what interests you.</p>

<div class="gxd-callout gxd-callout-green">
  <div class="gxd-callout-title">✅ Convention</div>
  <p>Throughout this reference, <code>→</code> means "evaluates to" or "produces", and <code>// ...</code> denotes comments that are ignored by the compiler.</p>
</div>
`,

/* ─── QUICK START ────────────────────────────────────────── */
quickstart: `
<h1>Quick Start</h1>
<p>The fastest path from zero to a running bot.</p>

<h2>Your first bot</h2>
<p>Create a new file called <code>main.grav</code> and write:</p>

<pre class="gxd-code-raw">// My first Gravitix bot

on /start {
    emit "Hello, {ctx.first_name}! 👋";
    emit "I am your new bot. Try /help";
}

on /help {
    emit "Available commands:";
    emit "/start — greet me";
    emit "/echo — repeat a message";
}

on /echo {
    emit "You said: {ctx.text}";
}</pre>

<div class="gxd-callout gxd-callout-purple">
  <div class="gxd-callout-title">🚀 What just happened?</div>
  <ul>
    <li><code>on /start { ... }</code> — defines a handler that runs when a user sends <strong>/start</strong></li>
    <li><code>emit "..."</code> — sends a message back to the user</li>
    <li><code>{ctx.first_name}</code> — interpolates the user's first name into the string</li>
  </ul>
</div>

<h2>Running the bot</h2>
<p>In the Gravitix IDE, click the <strong>Run ▶</strong> button in the top bar. Enter your Vortex Bot Token when prompted. The bot starts immediately — no build step needed.</p>

<h2>Project structure</h2>
<p>A Gravitix project is a single directory containing <code>.grav</code> files. The entry point is always the file you choose to run.</p>

<pre class="gxd-code-raw">my-bot/
├── main.grav       ← entry point
├── helpers.grav    ← shared functions (future)
└── README.md</pre>

<h2>A slightly larger example</h2>
<pre class="gxd-code-raw">state {
    clicks: int = 0,
}

on /start {
    emit "Welcome! Press /click to count.";
}

on /click {
    state.clicks += 1;
    emit "You have clicked {state.clicks} time(s)!";
}

on /reset {
    state.clicks = 0;
    emit "Counter reset.";
}</pre>

<div class="gxd-callout gxd-callout-blue">
  <div class="gxd-callout-title">ℹ️ State</div>
  <p><code>state { ... }</code> declares persistent variables that survive across messages. We cover this in depth in the <em>State Management</em> section.</p>
</div>
`,

/* ─── SYNTAX AT A GLANCE ─────────────────────────────────── */
syntax: `
<h1>Syntax at a Glance</h1>
<p>Every Gravitix program is built from three basic building blocks: <strong>handlers</strong>, <strong>emit statements</strong>, and <strong>logic</strong>. This page breaks down exactly what goes where.</p>

<h2>Anatomy of a handler</h2>

<pre class="gxd-code-raw">on &lt;trigger&gt; {
    &lt;statements&gt;
}</pre>

<p><code>on</code> — keyword. Always the same.<br>
<code>&lt;trigger&gt;</code> — what event to listen for (see table below).<br>
<code>{ ... }</code> — the body: any number of statements that run when the event fires.</p>

<h2>What goes after <code>on</code></h2>
<p>The trigger tells the bot <em>when</em> to run the handler body:</p>

<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>You write</span><span>Runs when user sends…</span></div>
  <div class="gxd-type-row"><code>on /start</code><span>The command <code>/start</code></span></div>
  <div class="gxd-type-row"><code>on /help</code><span>The command <code>/help</code></span></div>
  <div class="gxd-type-row"><code>on /buy_ticket</code><span>The command <code>/buy_ticket</code> (any name you choose)</span></div>
  <div class="gxd-type-row"><code>on msg</code><span>Any plain text message (not a command)</span></div>
  <div class="gxd-type-row"><code>on photo</code><span>A photo</span></div>
  <div class="gxd-type-row"><code>on voice</code><span>A voice message</span></div>
  <div class="gxd-type-row"><code>on video</code><span>A video</span></div>
  <div class="gxd-type-row"><code>on sticker</code><span>A sticker</span></div>
  <div class="gxd-type-row"><code>on document</code><span>A file / document</span></div>
  <div class="gxd-type-row"><code>on any</code><span>Absolutely any event — catch-all</span></div>
</div>

<pre class="gxd-code-raw">on /start   { emit "Welcome!"; }
on /help    { emit "Here is help."; }
on msg      { emit "You wrote: {ctx.text}"; }
on photo    { emit "Nice photo! 📸"; }
on voice    { emit "Got your voice message 🎤"; }
on any      { emit "Something happened."; }</pre>

<h2>What goes after <code>emit</code></h2>
<p><code>emit</code> sends a message to the user. After it you put <em>the value to send</em>:</p>

<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>You write</span><span>User receives</span></div>
  <div class="gxd-type-row"><code>emit "Hello!";</code><span>The text: Hello!</span></div>
  <div class="gxd-type-row"><code>emit "Hi, {ctx.first_name}!";</code><span>The text with the user's name inserted</span></div>
  <div class="gxd-type-row"><code>emit greeting;</code><span>The value stored in the variable <code>greeting</code></span></div>
  <div class="gxd-type-row"><code>emit "Count: {state.n}";</code><span>A string with the current state value</span></div>
  <div class="gxd-type-row"><code>emit str(42);</code><span>The text: 42</span></div>
</div>

<pre class="gxd-code-raw">// Literal string
emit "Hello!";

// String with interpolation — {expression} is replaced with its value
emit "Welcome, {ctx.first_name}!";
emit "You have {state.coins} coins.";
emit "2 + 2 = {2 + 2}";

// Variable
let greeting = "Good morning!";
emit greeting;

// Result of a function
emit str(state.score);
emit "Length: {len(ctx.text)}";</pre>

<h2>Multiple emits = multiple messages</h2>
<p>Each <code>emit</code> sends a separate message. They arrive one after another:</p>

<pre class="gxd-code-raw">on /start {
    emit "Welcome! 👋";
    emit "This bot helps you track tasks.";
    emit "Type /help to see all commands.";
}
// → user receives 3 separate messages</pre>

<h2>Multiple handlers for the same trigger</h2>
<p>You can write several <code>on /command</code> handlers. They are checked in order — the first one whose <strong>guard</strong> passes runs. See <em>Guard Clauses</em> for details.</p>

<pre class="gxd-code-raw">on /buy guard state.stock > 0 {
    state.stock -= 1;
    emit "Purchase successful! Stock left: {state.stock}";
}

on /buy {
    // guard above failed — stock is 0
    emit "Sorry, out of stock!";
}</pre>

<div class="gxd-callout gxd-callout-green">
  <div class="gxd-callout-title">✅ Summary</div>
  <ul>
    <li><code>on &lt;trigger&gt;</code> — choose what event fires the handler</li>
    <li><code>emit &lt;value&gt;</code> — send a message; the value is a string, variable, or any expression</li>
    <li>Multiple <code>emit</code> lines → multiple separate messages to the user</li>
    <li>Multiple handlers for the same trigger → checked top to bottom, first match wins</li>
  </ul>
</div>
`,

/* ─── VARIABLES ──────────────────────────────────────────── */
variables: `
<h1>Variables</h1>
<p>Variables store values that you can use and change throughout your program.</p>

<h2>Declaring variables</h2>
<p>Use the <code>let</code> keyword:</p>

<pre class="gxd-code-raw">let x = 42;
let name = "Alice";
let active = true;
let price = 9.99;</pre>

<p>The compiler infers the type from the value on the right-hand side. You never need to write the type explicitly — but you <em>can</em>.</p>

<h2>Explicit type annotations</h2>
<p>Add <code>: TypeName</code> after the variable name:</p>

<pre class="gxd-code-raw">let count: int   = 0;
let label: str   = "hello";
let score: float = 3.14;
let done:  bool  = false;</pre>

<div class="gxd-callout gxd-callout-blue">
  <div class="gxd-callout-title">ℹ️ When to annotate</div>
  <p>Annotations are optional — use them when the type is not obvious from the value, or when you want the code to be self-documenting.</p>
</div>

<h2>Updating variables</h2>
<p>Variables are mutable by default. Assign a new value with <code>=</code>:</p>

<pre class="gxd-code-raw">let score = 0;
score = score + 10;    // score is now 10
score += 5;            // score is now 15
score -= 3;            // score is now 12
score *= 2;            // score is now 24
score /= 4;            // score is now 6</pre>

<h2>Naming rules</h2>
<ul>
  <li>Must start with a letter or underscore: <code>name</code>, <code>_temp</code></li>
  <li>Can contain letters, digits, underscores: <code>user_count</code>, <code>page2</code></li>
  <li>Case-sensitive: <code>count</code> and <code>Count</code> are different</li>
  <li>Cannot be a keyword: <code>let</code>, <code>fn</code>, <code>on</code>, <code>if</code>…</li>
</ul>

<div class="gxd-callout gxd-callout-green">
  <div class="gxd-callout-title">✅ Convention</div>
  <p>Use <strong>snake_case</strong> for variables and functions: <code>user_name</code>, <code>message_count</code>.</p>
</div>

<h2>Scope</h2>
<p>Variables exist within the block <code>{ }</code> they are declared in. They are not visible outside that block:</p>

<pre class="gxd-code-raw">on /start {
    let greeting = "Hello!";
    emit greeting;            // ✅ works
}
// greeting is not accessible here</pre>
`,

/* ─── TYPES ──────────────────────────────────────────────── */
types: `
<h1>Types</h1>
<p>Every value in Gravitix has a type. The type system is <strong>static</strong>: types are checked at compile time, before your bot runs.</p>

<h2>Primitive types</h2>

<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header">
    <span>Type</span><span>Size</span><span>Description</span><span>Example</span>
  </div>
  <div class="gxd-type-row">
    <code>int</code><span>64-bit</span><span>Whole number, positive or negative</span><code>42, -7, 0</code>
  </div>
  <div class="gxd-type-row">
    <code>float</code><span>64-bit</span><span>Decimal number (IEEE 754)</span><code>3.14, -0.5</code>
  </div>
  <div class="gxd-type-row">
    <code>bool</code><span>1-bit</span><span>True or false</span><code>true, false</code>
  </div>
  <div class="gxd-type-row">
    <code>str</code><span>UTF-8</span><span>Text string, any length</span><code>"hello", ""</code>
  </div>
  <div class="gxd-type-row">
    <code>void</code><span>—</span><span>No value (function return)</span><code>—</code>
  </div>
</div>

<h2>int</h2>
<p>A 64-bit signed integer. Supports values from about <code>−9.2 × 10¹⁸</code> to <code>+9.2 × 10¹⁸</code>.</p>

<pre class="gxd-code-raw">let age: int = 25;
let temp = -10;         // inferred as int
let big = 1_000_000;    // underscores for readability</pre>

<h2>float</h2>
<p>A 64-bit double-precision floating-point number.</p>

<pre class="gxd-code-raw">let pi: float = 3.14159;
let rate = 0.075;
let result = 10.0 / 3.0;    // → 3.3333...</pre>

<div class="gxd-callout gxd-callout-yellow">
  <div class="gxd-callout-title">⚠️ Integer division</div>
  <p><code>10 / 3</code> with two <code>int</code> values gives <code>3</code> (truncated). Use <code>10.0 / 3.0</code> for decimal results.</p>
</div>

<h2>bool</h2>
<p>Has exactly two values: <code>true</code> and <code>false</code>.</p>

<pre class="gxd-code-raw">let is_admin = false;
let logged_in = true;

if is_admin {
    emit "Admin panel";
}</pre>

<h2>str</h2>
<p>A Unicode text string. Strings are immutable values.</p>

<pre class="gxd-code-raw">let name = "Alice";
let empty = "";
let greeting = "Hello, {name}!";    // interpolation</pre>

<h2>list&lt;T&gt;</h2>
<p>An ordered sequence of values, all of the same type <code>T</code>.</p>

<pre class="gxd-code-raw">let nums: list&lt;int&gt;  = [1, 2, 3, 4, 5];
let tags: list&lt;str&gt;  = ["Rust", "Go", "Python"];
let empty: list&lt;int&gt; = [];

// Access by index (0-based)
let first = nums[0];   // → 1
let last  = nums[4];   // → 5

// Length
let n = len(nums);     // → 5</pre>

<div class="gxd-callout gxd-callout-blue">
  <div class="gxd-callout-title">ℹ️ Index bounds</div>
  <p>Accessing an index out of range (e.g., <code>nums[99]</code> when the list has 5 elements) returns <code>null</code> rather than crashing your bot.</p>
</div>

<h2>map&lt;K, V&gt;</h2>
<p>A collection of key-value pairs. Keys must all be the same type, values must all be the same type.</p>

<pre class="gxd-code-raw">let scores: map&lt;str, int&gt; = {};

// Insert / update
scores["Alice"] = 100;
scores["Bob"]   = 85;

// Read
let alice_score = scores["Alice"];   // → 100

// Check if key exists
if scores["Charlie"] == null {
    emit "Charlie not found";
}</pre>

<h2>void</h2>
<p>The return type of functions that do not return a value. You rarely write <code>void</code> explicitly — it is the default when no return type is specified.</p>

<pre class="gxd-code-raw">fn greet_user() {        // implicitly returns void
    emit "Hello!";
}

fn add(a: int, b: int) -> int {
    return a + b;
}</pre>

<h2>null</h2>
<p>Some values can be absent. Optional fields in <code>ctx</code> (like <code>ctx.username</code>) may be <code>null</code>. Always check before using:</p>

<pre class="gxd-code-raw">if ctx.username != null {
    emit "Your username: @{ctx.username}";
} else {
    emit "You have no username set.";
}</pre>

<h2>Optional types  T?</h2>
<p>Adding <code>?</code> after a type marks it as <strong>optional</strong> — the value may be <code>null</code>. This is how function parameters and state fields express "this may or may not be present":</p>

<pre class="gxd-code-raw">// State field that starts null until assigned
state {
    username: str? = null,
    score:    int  = 0,
}

on /setname {
    let parts = split(ctx.text, " ");
    if len(parts) >= 2 {
        state.username = parts[1];
        emit "Name saved: {state.username}";
    }
}

on /profile {
    if state.username == null {
        emit "No name set. Use /setname &lt;name&gt;";
    } else {
        emit "Name: {state.username} | Score: {state.score}";
    }
}</pre>

<div class="gxd-callout gxd-callout-blue">
  <div class="gxd-callout-title">ℹ️ Rule of thumb</div>
  <p>If a value might not always exist, annotate it <code>T?</code> and always check <code>!= null</code> before using it. Accessing a <code>null</code> field does not crash the bot — it returns <code>null</code> silently.</p>
</div>
`,

/* ─── OPERATORS ──────────────────────────────────────────── */
operators: `
<h1>Operators</h1>
<p>Operators combine values to produce new values.</p>

<h2>Arithmetic operators</h2>

<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Operator</span><span>Meaning</span><span>Example</span><span>Result</span></div>
  <div class="gxd-type-row"><code>+</code><span>Addition</span><code>3 + 4</code><code>7</code></div>
  <div class="gxd-type-row"><code>-</code><span>Subtraction</span><code>10 - 3</code><code>7</code></div>
  <div class="gxd-type-row"><code>*</code><span>Multiplication</span><code>6 * 7</code><code>42</code></div>
  <div class="gxd-type-row"><code>/</code><span>Division</span><code>10 / 2</code><code>5</code></div>
  <div class="gxd-type-row"><code>%</code><span>Remainder (modulo)</span><code>10 % 3</code><code>1</code></div>
  <div class="gxd-type-row"><code>**</code><span>Power (exponentiation)</span><code>2 ** 8</code><code>256</code></div>
</div>

<pre class="gxd-code-raw">let a = 10;
let b = 3;
let sum  = a + b;    // 13
let diff = a - b;    // 7
let prod = a * b;    // 30
let quot = a / b;    // 3  (integer division)
let rem  = a % b;    // 1
let exp  = 2 ** 8;   // 256</pre>

<h2>Assignment operators</h2>

<pre class="gxd-code-raw">let x = 10;
x += 5;    // x = x + 5  → 15
x -= 3;    // x = x - 3  → 12
x *= 2;    // x = x * 2  → 24
x /= 4;    // x = x / 4  → 6
x %= 4;    // x = x % 4  → 2</pre>

<h2>Comparison operators</h2>
<p>Return <code>bool</code>:</p>

<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Operator</span><span>Meaning</span><span>Example</span></div>
  <div class="gxd-type-row"><code>==</code><span>Equal</span><code>5 == 5  → true</code></div>
  <div class="gxd-type-row"><code>!=</code><span>Not equal</span><code>5 != 4  → true</code></div>
  <div class="gxd-type-row"><code>&lt;</code><span>Less than</span><code>3 &lt; 7  → true</code></div>
  <div class="gxd-type-row"><code>&gt;</code><span>Greater than</span><code>9 &gt; 5  → true</code></div>
  <div class="gxd-type-row"><code>&lt;=</code><span>Less or equal</span><code>4 &lt;= 4  → true</code></div>
  <div class="gxd-type-row"><code>&gt;=</code><span>Greater or equal</span><code>6 &gt;= 7  → false</code></div>
</div>

<h2>Logical operators</h2>

<pre class="gxd-code-raw">true  && true   // → true    (AND)
true  && false  // → false
false || true   // → true    (OR)
false || false  // → false
!true           // → false   (NOT)
!false          // → true</pre>

<pre class="gxd-code-raw">if age >= 18 && is_verified {
    emit "Access granted";
}

if is_banned || is_bot {
    return;
}</pre>

<h2>String concatenation</h2>
<p>Use <code>+</code> to join strings:</p>

<pre class="gxd-code-raw">let first = "Hello";
let second = " World";
let combined = first + second;    // "Hello World"</pre>

<h2>Operator precedence</h2>
<p>Higher rows bind tighter (evaluated first):</p>

<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Precedence</span><span>Operators</span></div>
  <div class="gxd-type-row"><span>Highest</span><code>!  (unary -)</code></div>
  <div class="gxd-type-row"><span></span><code>**</code></div>
  <div class="gxd-type-row"><span></span><code>*  /  %</code></div>
  <div class="gxd-type-row"><span></span><code>+  -</code></div>
  <div class="gxd-type-row"><span></span><code>&lt;  &gt;  &lt;=  &gt;=</code></div>
  <div class="gxd-type-row"><span></span><code>==  !=</code></div>
  <div class="gxd-type-row"><span></span><code>&amp;&amp;</code></div>
  <div class="gxd-type-row"><span>Lowest</span><code>||</code></div>
</div>

<p>Use parentheses to override: <code>(a + b) * c</code>.</p>
`,

/* ─── STRINGS ────────────────────────────────────────────── */
strings: `
<h1>Strings</h1>
<p>Strings in Gravitix are UTF-8 encoded text. They support rich interpolation and a suite of built-in operations.</p>

<h2>String literals</h2>
<p>Write a string between double quotes:</p>

<pre class="gxd-code-raw">let name = "Alice";
let empty = "";
let sentence = "The quick brown fox.";</pre>

<h2>String interpolation</h2>
<p>Embed any expression inside <code>{}</code> within a string:</p>

<pre class="gxd-code-raw">let name = "Alice";
let age  = 30;

emit "Hello, {name}!";              // "Hello, Alice!"
emit "You are {age} years old.";    // "You are 30 years old."
emit "2 + 2 = {2 + 2}";            // "2 + 2 = 4"
emit "Items: {len(my_list)}";       // "Items: 3"</pre>

<div class="gxd-callout gxd-callout-purple">
  <div class="gxd-callout-title">✨ Tip</div>
  <p>You can put any valid expression inside <code>{ }</code> — function calls, arithmetic, comparisons. There is no limit on complexity.</p>
</div>

<h2>Escape sequences</h2>

<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Sequence</span><span>Result</span></div>
  <div class="gxd-type-row"><code>\\n</code><span>Newline</span></div>
  <div class="gxd-type-row"><code>\\t</code><span>Tab</span></div>
  <div class="gxd-type-row"><code>\\"</code><span>Double quote</span></div>
  <div class="gxd-type-row"><code>\\\\</code><span>Backslash</span></div>
</div>

<pre class="gxd-code-raw">emit "Line 1\\nLine 2";     // sends two lines
emit "Tab\\there";          // tab character</pre>

<h2>Multiline strings</h2>
<p>Use triple double-quotes <code>"""..."""</code> for strings that span multiple lines:</p>

<pre class="gxd-code-raw">let msg = """
Welcome to the bot!

Commands:
/help   — show help
/start  — restart
""";
emit msg;</pre>

<div class="gxd-callout gxd-callout-blue">
  <div class="gxd-callout-title">ℹ️ Triple-quote strings</div>
  <p>Triple-quoted strings preserve all whitespace and newlines exactly as written. Interpolation <code>{}</code> works inside them the same way.</p>
</div>

<h2>Escape sequences</h2>

<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Sequence</span><span>Result</span></div>
  <div class="gxd-type-row"><code>\\n</code><span>Newline (new line)</span></div>
  <div class="gxd-type-row"><code>\\t</code><span>Tab character</span></div>
  <div class="gxd-type-row"><code>\\r</code><span>Carriage return</span></div>
  <div class="gxd-type-row"><code>\\"</code><span>Literal double-quote character</span></div>
  <div class="gxd-type-row"><code>\\\\</code><span>Literal backslash</span></div>
  <div class="gxd-type-row"><code>\\{</code><span>Literal <code>{</code> — prevents interpolation</span></div>
</div>

<pre class="gxd-code-raw">emit "Line 1\\nLine 2";         // sends two lines
emit "Price: \\{amount}";       // sends literal: Price: {amount}
emit "Tab\\there";</pre>

<h2>String operations via built-ins</h2>

<pre class="gxd-code-raw">let s = "  Hello, World!  ";

len(s)                    // → 18
trim(s)                   // → "Hello, World!"
lowercase(s)              // → "  hello, world!  "
uppercase(s)              // → "  HELLO, WORLD!  "
contains(s, "World")      // → true
replace(s, "World", "Gravitix")  // → "  Hello, Gravitix!  "
split("a,b,c", ",")       // → ["a", "b", "c"]</pre>

<h2>Method syntax on strings</h2>
<p>You can call many string functions using dot notation — both styles are equivalent:</p>

<pre class="gxd-code-raw">let s = "  Hello, World!  ";

// Function-call style        Method-call style
trim(s)                    //  s.trim()
lowercase(s)               //  s.to_lower()
uppercase(s)               //  s.to_upper()
len(s)                     //  s.len()
contains(s, "World")       //  s.contains("World")
split(s, ",")              //  s.split(",")
replace(s, "x", "y")      //  s.replace("x", "y")

// Method chaining reads naturally left-to-right:
let clean = ctx.text.trim().to_lower();

// starts_with / ends_with (method-only)
if ctx.text.starts_with("/") {
    emit "That looks like a command";
}
if ctx.text.ends_with("?") {
    emit "You asked a question";
}</pre>

<h2>Checking an empty string</h2>

<pre class="gxd-code-raw">let msg = ctx.text;
if len(msg) == 0 {
    emit "Please send some text!";
    return;
}</pre>

<h2>Building strings dynamically</h2>

<pre class="gxd-code-raw">let result = "";
for item in my_list {
    result = result + item + "\\n";
}
emit result;</pre>
`,

/* ─── CONTROL FLOW: IF ───────────────────────────────────── */
if: `
<h1>if / elif / else</h1>
<p>Conditional execution: run different code depending on a condition.</p>

<h2>Basic if</h2>
<pre class="gxd-code-raw">if score > 90 {
    emit "Excellent!";
}</pre>

<h2>if / else</h2>
<pre class="gxd-code-raw">if is_admin {
    emit "Welcome, administrator.";
} else {
    emit "Welcome, user.";
}</pre>

<h2>if / elif / else</h2>
<p>Use <code>elif</code> for multiple branches. Only the first matching branch runs:</p>

<pre class="gxd-code-raw">let score = 72;

if score >= 90 {
    emit "A";
} elif score >= 80 {
    emit "B";
} elif score >= 70 {
    emit "C";
} elif score >= 60 {
    emit "D";
} else {
    emit "F";
}</pre>

<h2>Nested conditions</h2>
<pre class="gxd-code-raw">if is_registered {
    if has_subscription {
        emit "Premium user, full access.";
    } else {
        emit "Free user, limited access.";
    }
} else {
    emit "Please register first with /register";
}</pre>

<div class="gxd-callout gxd-callout-green">
  <div class="gxd-callout-title">✅ Tip</div>
  <p>Deep nesting makes code hard to read. Prefer <code>return</code> early to flatten branches:</p>
  <pre class="gxd-code-raw">if !is_registered { emit "Please register."; return; }
if !has_subscription { emit "Please subscribe."; return; }
emit "Welcome, premium user!";</pre>
</div>

<h2>Conditions</h2>
<p>Any expression that evaluates to <code>bool</code> works as a condition:</p>

<pre class="gxd-code-raw">if x > 0 && x < 100 { ... }
if name == "Alice" || name == "Bob" { ... }
if !done { ... }
if len(list) > 0 { ... }</pre>
`,

/* ─── LOOPS ──────────────────────────────────────────────── */
loops: `
<h1>Loops</h1>
<p>Repeat a block of code multiple times.</p>

<h2>while loop</h2>
<p>Runs as long as the condition is <code>true</code>:</p>

<pre class="gxd-code-raw">let count = 0;
while count < 5 {
    emit "Count: {count}";
    count += 1;
}
// Prints: Count: 0, Count: 1, ... Count: 4</pre>

<div class="gxd-callout gxd-callout-yellow">
  <div class="gxd-callout-title">⚠️ Infinite loops</div>
  <p>Make sure the condition eventually becomes <code>false</code>, or use <code>break</code> to exit. The runtime protects against truly infinite loops with a step limit.</p>
</div>

<h2>for … in loop</h2>
<p>Iterate over every element in a list:</p>

<pre class="gxd-code-raw">let fruits = ["apple", "banana", "cherry"];

for fruit in fruits {
    emit "I like {fruit}";
}
// → "I like apple"
// → "I like banana"
// → "I like cherry"</pre>

<h2>Iterating with index</h2>
<p>Use <code>range(start, end)</code> to loop by number:</p>

<pre class="gxd-code-raw">for i in range(0, 5) {
    emit "Step {i}";
}
// → Step 0, Step 1, Step 2, Step 3, Step 4</pre>

<h2>break and continue</h2>

<pre class="gxd-code-raw">// break — exit the loop immediately
let i = 0;
while true {
    if i >= 3 { break; }
    emit "i = {i}";
    i += 1;
}

// continue — skip to the next iteration
for n in range(0, 10) {
    if n % 2 == 0 { continue; }    // skip even numbers
    emit "{n}";                      // prints: 1, 3, 5, 7, 9
}</pre>

<h2>Building output in a loop</h2>

<pre class="gxd-code-raw">let items = ["🍎 Apple", "🍌 Banana", "🍇 Grapes"];
let menu = "Today's menu:\\n";
for item in items {
    menu = menu + "• " + item + "\\n";
}
emit menu;</pre>
`,

/* ─── MATCH ──────────────────────────────────────────────── */
match: `
<h1>match Expression</h1>
<p>Pattern-match a value against multiple patterns. Think of it as a powerful <code>switch</code> statement.</p>

<h2>Basic match</h2>
<pre class="gxd-code-raw">match ctx.text {
    "hello" => emit "Hi there! 👋",
    "bye"   => emit "Goodbye! 👋",
    "help"  => emit "Type a greeting or farewell.",
    _       => emit "I don't understand: {ctx.text}",
}</pre>

<p><code>_</code> is the <strong>wildcard</strong> — it matches anything that did not match earlier arms.</p>

<h2>Matching numbers</h2>
<pre class="gxd-code-raw">let score = 42;
match score {
    0        => emit "Zero!",
    1        => emit "One",
    42       => emit "The answer to everything! ✨",
    _        => emit "Some other number: {score}",
}</pre>

<h2>Regex patterns</h2>
<p>Match against regular expressions with <code>/pattern/flags</code>:</p>

<pre class="gxd-code-raw">match ctx.text {
    /hello|hi|hey/i  => emit "Hey! 👋",
    /bye|cya|later/i => emit "See you! 👋",
    /\\d+/           => emit "You sent a number",
    _                => emit "Unknown input",
}</pre>

<div class="gxd-callout gxd-callout-blue">
  <div class="gxd-callout-title">ℹ️ Regex flags</div>
  <ul>
    <li><code>i</code> — case-insensitive matching</li>
    <li><code>g</code> — global (match all occurrences)</li>
  </ul>
</div>

<h2>Multi-statement arms</h2>
<p>Use a block <code>{ ... }</code> when you need more than one statement:</p>

<pre class="gxd-code-raw">match ctx.text {
    "status" => {
        let count = state.visitors;
        emit "Visitors today: {count}";
        emit "Bot is running normally.";
    },
    "reset" => {
        state.visitors = 0;
        emit "Counter reset!";
    },
    _ => emit "Unknown command",
}</pre>

<h2>Matching booleans</h2>
<pre class="gxd-code-raw">match is_admin {
    true  => emit "Admin area",
    false => emit "User area",
}</pre>
`,

/* ─── FUNCTIONS ──────────────────────────────────────────── */
functions: `
<h1>Functions</h1>
<p>Functions are reusable blocks of code. They help you avoid repetition and make code easier to understand.</p>

<h2>Declaring a function</h2>
<p>Use the <code>fn</code> keyword:</p>

<pre class="gxd-code-raw">fn say_hello() {
    emit "Hello, World!";
}</pre>

<h2>Parameters</h2>
<p>Pass data into a function with parameters (name: type):</p>

<pre class="gxd-code-raw">fn greet(name: str) {
    emit "Hello, {name}!";
}

fn add(a: int, b: int) {
    emit "Sum: {a + b}";
}</pre>

<h2>Return values</h2>
<p>Declare the return type after <code>-></code> and use <code>return</code>:</p>

<pre class="gxd-code-raw">fn add(a: int, b: int) -> int {
    return a + b;
}

fn is_even(n: int) -> bool {
    return n % 2 == 0;
}

fn make_greeting(name: str) -> str {
    return "Hello, " + name + "!";
}</pre>

<h2>Calling functions</h2>
<pre class="gxd-code-raw">greet("Alice");              // calls greet, no return value used
let sum = add(3, 4);         // sum = 7
let greeting = make_greeting("Bob");  // greeting = "Hello, Bob!"

emit greeting;
emit "5 is even: {is_even(5)}";</pre>

<h2>Generic type parameters</h2>
<p>Use angle brackets for generic types in parameters:</p>

<pre class="gxd-code-raw">fn first_item(items: list&lt;str&gt;) -> str {
    return items[0];
}

fn count_items(items: list&lt;int&gt;) -> int {
    return len(items);
}</pre>

<h2>Recursion</h2>
<p>A function can call itself (with care to avoid infinite recursion):</p>

<pre class="gxd-code-raw">fn factorial(n: int) -> int {
    if n <= 1 { return 1; }
    return n * factorial(n - 1);
}

on /factorial {
    let result = factorial(5);    // → 120
    emit "5! = {result}";
}</pre>

<div class="gxd-callout gxd-callout-yellow">
  <div class="gxd-callout-title">⚠️ Recursion limit</div>
  <p>The runtime enforces a maximum call depth (typically 200) to prevent stack overflows.</p>
</div>

<h2>Organizing code with functions</h2>
<pre class="gxd-code-raw">fn format_user_info(id: int, name: str, score: int) -> str {
    return "👤 {name} (id:{id}) — score: {score}";
}

fn is_high_score(score: int) -> bool {
    return score >= 100;
}

on /profile {
    let info = format_user_info(ctx.user_id, ctx.first_name, state.score);
    emit info;
    if is_high_score(state.score) {
        emit "🏆 Top performer!";
    }
}</pre>
`,

/* ─── HANDLERS ───────────────────────────────────────────── */
handlers: `
<h1>Event Handlers</h1>
<p>Handlers are the heart of a Gravitix bot. Each handler listens for a specific type of event and runs when that event occurs.</p>

<h2>Command handlers</h2>
<p>Vortex commands start with <code>/</code>. Match them with:</p>

<pre class="gxd-code-raw">on /start  { emit "Welcome!"; }
on /help   { emit "Here is help."; }
on /status { emit "Bot is running."; }</pre>

<h2>Message handler</h2>
<p>Runs for any plain text message (not a command):</p>

<pre class="gxd-code-raw">on msg {
    emit "You said: {ctx.text}";
}</pre>

<h2>All event types</h2>

<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Event</span><span>Triggers when user sends…</span></div>
  <div class="gxd-type-row"><code>on /command</code><span>A slash command, e.g. /start</span></div>
  <div class="gxd-type-row"><code>on msg</code><span>Any text message (non-command)</span></div>
  <div class="gxd-type-row"><code>on photo</code><span>A photo or image</span></div>
  <div class="gxd-type-row"><code>on voice</code><span>A voice message</span></div>
  <div class="gxd-type-row"><code>on video</code><span>A video file</span></div>
  <div class="gxd-type-row"><code>on sticker</code><span>A sticker</span></div>
  <div class="gxd-type-row"><code>on document</code><span>A file/document</span></div>
  <div class="gxd-type-row"><code>on location</code><span>A location share</span></div>
  <div class="gxd-type-row"><code>on contact</code><span>A shared contact card</span></div>
  <div class="gxd-type-row"><code>on any</code><span>Every event, regardless of type — catch-all fallback</span></div>
</div>

<h2>Multiple handlers</h2>
<p>You can define as many handlers as you need. They run independently:</p>

<pre class="gxd-code-raw">on /start {
    state.visits += 1;
    emit "Welcome! Visit #{state.visits}";
}

on photo {
    emit "Nice photo! 📸";
}

on voice {
    emit "Voice received! 🎤";
}

on sticker {
    emit "Cool sticker! 😄";
}

on msg {
    // This runs for all other text messages
    emit "You wrote: {ctx.text}";
}</pre>

<h2>Handler with arguments</h2>
<p>Commands can include arguments. The full message (command + args) is available via <code>ctx.text</code>:</p>

<pre class="gxd-code-raw">on /echo {
    // ctx.text for /echo hello world → "/echo hello world"
    let parts = split(ctx.text, " ");
    if len(parts) < 2 {
        emit "Usage: /echo &lt;message&gt;";
        return;
    }
    // Reassemble everything after the command
    emit "Echo: {ctx.text}";
}</pre>

<div class="gxd-callout gxd-callout-blue">
  <div class="gxd-callout-title">ℹ️ Handler ordering</div>
  <p>When multiple handlers could match, they are checked in the order they are written. The first match wins. The <code>on msg</code> handler is typically last as a fallback.</p>
</div>
`,

/* ─── GUARD ──────────────────────────────────────────────── */
guard: `
<h1>Guard Clauses</h1>
<p>Guards let you add a condition to a handler. The handler only runs if the guard evaluates to <code>true</code>.</p>

<h2>Basic guard</h2>
<pre class="gxd-code-raw">on /admin guard ctx.is_admin {
    emit "Welcome to the admin panel.";
}

on /admin {
    emit "You do not have admin access.";
}</pre>

<p>If the user is not an admin, the first handler's guard fails, and Gravitix falls through to the second handler.</p>

<h2>Complex guard conditions</h2>
<pre class="gxd-code-raw">on /premium guard ctx.is_premium && !ctx.is_banned {
    emit "Premium content unlocked!";
}

on /greet guard ctx.first_name == "Alice" {
    emit "Hello, Alice! Special welcome for you 🌟";
}

on /greet {
    emit "Hello, {ctx.first_name}!";
}</pre>

<h2>Guard with state</h2>
<pre class="gxd-code-raw">on /buy guard state.items_in_stock > 0 {
    state.items_in_stock -= 1;
    emit "Purchase successful! {state.items_in_stock} remaining.";
}

on /buy {
    emit "Sorry, out of stock!";
}</pre>

<div class="gxd-callout gxd-callout-green">
  <div class="gxd-callout-title">✅ Best practice</div>
  <p>Always provide a fallback handler without a guard to handle the case when all guarded handlers are skipped. This ensures users always receive a response.</p>
</div>

<h2>Multiple guards for the same command</h2>
<pre class="gxd-code-raw">on /settings guard ctx.is_admin {
    emit "Admin settings: /settoken, /setlang, /restart";
}

on /settings guard ctx.is_premium {
    emit "Premium settings: /theme, /notifications";
}

on /settings {
    emit "Basic settings: /language, /help";
}</pre>
`,

/* ─── CONTEXT ────────────────────────────────────────────── */
ctx: `
<h1>Context Object</h1>
<p>The <code>ctx</code> object is automatically available inside every handler. It contains information about the current message and the user who sent it.</p>

<h2>User information</h2>

<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Field</span><span>Type</span><span>Description</span></div>
  <div class="gxd-type-row"><code>ctx.user_id</code><span>int</span><span>Unique Vortex user ID</span></div>
  <div class="gxd-type-row"><code>ctx.first_name</code><span>str</span><span>User's first name</span></div>
  <div class="gxd-type-row"><code>ctx.last_name</code><span>str?</span><span>User's last name (may be null)</span></div>
  <div class="gxd-type-row"><code>ctx.username</code><span>str?</span><span>@username without @ (may be null)</span></div>
  <div class="gxd-type-row"><code>ctx.name</code><span>str</span><span>Full display name (first + last)</span></div>
  <div class="gxd-type-row"><code>ctx.lang</code><span>str?</span><span>User's language code, e.g. "en", "ru"</span></div>
  <div class="gxd-type-row"><code>ctx.is_bot</code><span>bool</span><span>True if sender is a bot account</span></div>
  <div class="gxd-type-row"><code>ctx.is_admin</code><span>bool</span><span>True if user is a group admin</span></div>
  <div class="gxd-type-row"><code>ctx.is_premium</code><span>bool</span><span>True if user has Vortex Premium</span></div>
</div>

<h2>Chat information</h2>

<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Field</span><span>Type</span><span>Description</span></div>
  <div class="gxd-type-row"><code>ctx.chat_id</code><span>int</span><span>Vortex chat / conversation ID</span></div>
  <div class="gxd-type-row"><code>ctx.chat_type</code><span>str</span><span>"private", "group", "supergroup", "channel"</span></div>
  <div class="gxd-type-row"><code>ctx.is_private</code><span>bool</span><span>True if it is a private conversation</span></div>
  <div class="gxd-type-row"><code>ctx.is_group</code><span>bool</span><span>True if it is a group chat</span></div>
</div>

<h2>Message information</h2>

<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Field</span><span>Type</span><span>Description</span></div>
  <div class="gxd-type-row"><code>ctx.text</code><span>str?</span><span>Message text (null for media)</span></div>
  <div class="gxd-type-row"><code>ctx.message_id</code><span>int</span><span>Unique ID of this message</span></div>
  <div class="gxd-type-row"><code>ctx.date</code><span>int</span><span>Unix timestamp of the message</span></div>
  <div class="gxd-type-row"><code>ctx.has_photo</code><span>bool</span><span>True if message contains a photo</span></div>
  <div class="gxd-type-row"><code>ctx.has_voice</code><span>bool</span><span>True if message contains voice audio</span></div>
  <div class="gxd-type-row"><code>ctx.has_video</code><span>bool</span><span>True if message contains video</span></div>
  <div class="gxd-type-row"><code>ctx.has_document</code><span>bool</span><span>True if message contains a file</span></div>
  <div class="gxd-type-row"><code>ctx.caption</code><span>str?</span><span>Caption text on media (may be null)</span></div>
</div>

<h2>Using context in practice</h2>
<pre class="gxd-code-raw">on /start {
    emit "Hello, {ctx.first_name}!";

    if ctx.username != null {
        emit "Your username: @{ctx.username}";
    } else {
        emit "You don't have a username set.";
    }

    if ctx.is_admin {
        emit "You are an admin in this chat.";
    }
}

on msg {
    if ctx.is_private {
        emit "Private chat message received.";
    } else {
        emit "Group message from {ctx.first_name}.";
    }
}</pre>

<h2>Personalized messages</h2>
<pre class="gxd-code-raw">fn get_greeting(name: str) -> str {
    let hour = int(now_unix() / 3600 % 24);    // rough hour
    if hour < 12 { return "Good morning, {name}! ☀️"; }
    elif hour < 17 { return "Good afternoon, {name}! 🌤️"; }
    else { return "Good evening, {name}! 🌙"; }
}

on /start {
    emit get_greeting(ctx.first_name);
}</pre>
`,

/* ─── STATE ──────────────────────────────────────────────── */
state: `
<h1>State Management</h1>
<p>State lets your bot remember things between messages. Without state, every message is independent and the bot has no memory.</p>

<h2>Declaring state</h2>
<p>Use a <code>state { }</code> block at the top level of your file:</p>

<pre class="gxd-code-raw">state {
    visits:    int = 0,
    last_user: str = "",
    scores:    map&lt;int, int&gt; = {},
    users:     list&lt;str&gt; = [],
}</pre>

<p>Each field has a name, a type, and a default value (used when the bot first starts).</p>

<div class="gxd-callout gxd-callout-blue">
  <div class="gxd-callout-title">ℹ️ Persistence</div>
  <p>State values survive between messages and between bot restarts. They are stored on disk automatically.</p>
</div>

<h2>Reading state</h2>
<p>Use <code>state.fieldname</code> anywhere in your code:</p>

<pre class="gxd-code-raw">on /stats {
    emit "Total visits: {state.visits}";
    emit "Last user: {state.last_user}";
}</pre>

<h2>Writing state</h2>
<pre class="gxd-code-raw">on /start {
    state.visits += 1;
    state.last_user = ctx.first_name;
    emit "Welcome! You are visitor #{state.visits}.";
}</pre>

<h2>Maps in state</h2>
<p>Maps in state are ideal for per-user data:</p>

<pre class="gxd-code-raw">state {
    scores: map&lt;int, int&gt; = {},
    names:  map&lt;int, str&gt; = {},
}

on /register {
    state.names[ctx.user_id] = ctx.first_name;
    state.scores[ctx.user_id] = 0;
    emit "Registered as {ctx.first_name}!";
}

on /score {
    let my_score = state.scores[ctx.user_id];
    if my_score == null {
        emit "You are not registered. Use /register";
        return;
    }
    emit "Your score: {my_score}";
}</pre>

<h2>Lists in state</h2>
<pre class="gxd-code-raw">state {
    todo_list: list&lt;str&gt; = [],
}

on /add {
    let task = ctx.text;    // the message text after /add
    push(state.todo_list, task);
    emit "Added: {task}";
}

on /list {
    if len(state.todo_list) == 0 {
        emit "Your list is empty.";
        return;
    }
    let output = "Your tasks:\\n";
    for i in range(0, len(state.todo_list)) {
        output = output + "{i+1}. {state.todo_list[i]}\\n";
    }
    emit output;
}</pre>

<h2>Resetting state</h2>
<pre class="gxd-code-raw">on /reset guard ctx.is_admin {
    state.visits = 0;
    state.scores = {};
    state.users  = [];
    emit "State cleared.";
}</pre>
`,

/* ─── FLOWS ──────────────────────────────────────────────── */
flows: `
<h1>Flows</h1>
<p>Flows let you write multi-step conversations in a linear, readable style. A flow can pause and wait for the user's next message.</p>

<h2>Declaring a flow</h2>
<pre class="gxd-code-raw">flow greet_user {
    emit "What is your name?";
    let name = wait msg;    // suspends here, resumes when user replies
    emit "Hello, {name}! Nice to meet you 🤝";
}</pre>

<h2>Triggering a flow</h2>
<p>Start a flow with <code>run flow &lt;name&gt;</code>:</p>

<pre class="gxd-code-raw">on /start {
    run flow greet_user;
}</pre>

<h2>The wait keyword</h2>
<p><code>wait</code> suspends the current flow until the specified event occurs. The value of the event is returned:</p>

<pre class="gxd-code-raw">let text_reply  = wait msg;      // wait for any text message
let photo_reply = wait photo;    // wait for a photo
let voice_reply = wait voice;    // wait for a voice message</pre>

<h2>Multi-step form</h2>
<pre class="gxd-code-raw">flow registration {
    emit "Let's set up your profile. What is your name?";
    let name = wait msg;

    emit "Hi, {name}! How old are you?";
    let age_str = wait msg;
    let age = int(age_str);

    emit "And your favourite programming language?";
    let lang = wait msg;

    // Save to state
    state.profiles[ctx.user_id] = "{name},{age},{lang}";

    emit "✅ Profile saved!";
    emit "Name: {name}, Age: {age}, Favourite: {lang}";
}

on /register {
    run flow registration;
}</pre>

<h2>Validation inside a flow</h2>
<pre class="gxd-code-raw">flow ask_age {
    let valid = false;
    let age = 0;

    while !valid {
        emit "Please enter your age (a number):";
        let reply = wait msg;
        age = int(reply);
        if age > 0 && age < 150 {
            valid = true;
        } else {
            emit "That doesn't look right. Try again.";
        }
    }

    emit "Got it! You are {age} years old.";
}</pre>

<div class="gxd-callout gxd-callout-purple">
  <div class="gxd-callout-title">✨ How flows work</div>
  <p>When a flow hits <code>wait</code>, it saves all its local variables and pauses. When the user sends the next message, the flow resumes exactly where it left off. This happens transparently — you just write linear code.</p>
</div>

<h2>Nested flows</h2>
<pre class="gxd-code-raw">flow ask_name {
    emit "What's your name?";
    return wait msg;
}

flow ask_city {
    emit "Which city are you from?";
    return wait msg;
}

flow full_profile {
    run flow ask_name;
    run flow ask_city;
    emit "Profile complete!";
}</pre>
`,

/* ─── EMIT ───────────────────────────────────────────────── */
emit: `
<h1>Emit & Messages</h1>
<p>Sending messages is the primary output of a bot. Gravitix provides several ways to send content.</p>

<h2>emit — send a text message</h2>
<pre class="gxd-code-raw">emit "Hello!";
emit "You have {state.points} points.";
emit "Line 1\\nLine 2\\nLine 3";</pre>

<h2>emit_to — send to a specific user</h2>
<p>Send a message to any user by their ID (useful in scheduled tasks or admin broadcasts):</p>

<pre class="gxd-code-raw">emit_to(ctx.user_id, "Your order is ready!");

// Notify admin
let admin_id = 123456789;
emit_to(admin_id, "New user registered: {ctx.first_name}");</pre>

<h2>Formatting tips</h2>
<pre class="gxd-code-raw">// Use emoji for visual appeal
emit "✅ Done!";
emit "❌ Error: invalid input";
emit "📊 Stats: {state.count} users";

// Multi-line messages
emit "Welcome to MyBot!\\n\\nHere are the commands:\\n/help — show this list\\n/start — restart\\n/settings — preferences";

// Dynamic content
let items = ["Apple 🍎", "Banana 🍌", "Cherry 🍒"];
let menu = "Today's menu:\\n";
for item in items {
    menu = menu + "• " + item + "\\n";
}
emit menu;</pre>

<h2>Conditional messaging</h2>
<pre class="gxd-code-raw">fn reply_score(score: int) {
    if score >= 90 {
        emit "🏆 Outstanding! Score: {score}";
    } elif score >= 70 {
        emit "👍 Good job! Score: {score}";
    } elif score >= 50 {
        emit "📚 Keep studying. Score: {score}";
    } else {
        emit "😟 Try again. Score: {score}";
    }
}

on /result {
    reply_score(state.scores[ctx.user_id]);
}</pre>
`,

/* ─── SCHEDULING ─────────────────────────────────────────── */
schedule: `
<h1>Scheduling</h1>
<p>Run code automatically on a schedule — no cron jobs, no external services needed.</p>

<h2>every — repeat on an interval</h2>
<pre class="gxd-code-raw">every 1 hour {
    emit_to(admin_id, "Hourly health check: bot is running ✅");
}

every 24 hours {
    emit_to(admin_id, "Daily report: {state.visits} visits today");
    state.visits = 0;    // reset daily counter
}

every 30 minutes {
    // Update something regularly
    state.tick += 1;
}</pre>

<h2>Time units</h2>

<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Unit</span><span>Example</span></div>
  <div class="gxd-type-row"><code>seconds / second</code><code>every 30 seconds</code></div>
  <div class="gxd-type-row"><code>minutes / minute</code><code>every 5 minutes</code></div>
  <div class="gxd-type-row"><code>hours / hour</code><code>every 1 hour</code></div>
</div>

<h2>at — run at a specific time of day</h2>
<pre class="gxd-code-raw">at "09:00" {
    emit_to(broadcast_channel, "🌅 Good morning everyone!");
}

at "12:00" {
    emit_to(broadcast_channel, "🍽️ Lunchtime reminder!");
}

at "22:00" {
    emit_to(broadcast_channel, "🌙 Good night, see you tomorrow!");
}</pre>

<div class="gxd-callout gxd-callout-yellow">
  <div class="gxd-callout-title">⚠️ Time zone</div>
  <p>Times in <code>at</code> are in UTC. If your users are in a different time zone, adjust accordingly (e.g., UTC+3 users: use "06:00" for 9 AM local).</p>
</div>

<h2>Combining scheduling with state</h2>
<pre class="gxd-code-raw">state {
    daily_visits: int = 0,
    total_visits:  int = 0,
    subscribers:   list&lt;int&gt; = [],
}

on /start {
    state.daily_visits  += 1;
    state.total_visits  += 1;
    push(state.subscribers, ctx.user_id);
    emit "Welcome!";
}

every 24 hours {
    let count = len(state.subscribers);
    emit_to(admin_id, "Daily report:\\n• Visits today: {state.daily_visits}\\n• Total users: {count}");
    state.daily_visits = 0;
}</pre>
`,

/* ─── PIPE ───────────────────────────────────────────────── */
pipe: `
<h1>Pipe Operator  |&gt;</h1>
<p>The pipe operator <code>|&gt;</code> passes a value as the first argument to the next function. It makes chaining operations readable, left to right.</p>

<h2>Basic usage</h2>
<pre class="gxd-code-raw">// Without pipe:
let result = trim(lowercase("  HELLO WORLD  "));

// With pipe — reads left to right:
let result = "  HELLO WORLD  " |> lowercase |> trim;
// Equivalent to: trim(lowercase("  HELLO WORLD  "))
// → "hello world"</pre>

<h2>Chaining multiple steps</h2>
<pre class="gxd-code-raw">let cleaned = ctx.text
    |> trim
    |> lowercase
    |> sanitize;    // remove dangerous HTML characters

// Process and send in one chain
ctx.text |> trim |> uppercase |> emit;</pre>

<h2>Passing additional arguments</h2>
<p>When a function needs more than one argument, the piped value becomes the <em>first</em> argument and the others go in parentheses:</p>

<pre class="gxd-code-raw">// split(string, separator) — string is piped in
let words = "one,two,three" |> split(",");
// → ["one", "two", "three"]

// replace(string, from, to) — string is piped in
let fixed = "Hello World" |> replace("World", "Gravitix");
// → "Hello Gravitix"</pre>

<h2>Real-world example</h2>
<pre class="gxd-code-raw">on msg {
    // Clean up user input before storing
    let normalized = ctx.text
        |> trim
        |> lowercase
        |> sanitize;

    if len(normalized) == 0 {
        emit "Please send a non-empty message.";
        return;
    }

    state.last_message = normalized;
    emit "Stored: {normalized}";
}</pre>

<h2>Why use pipe?</h2>

<div class="gxd-callout gxd-callout-green">
  <div class="gxd-callout-title">✅ Readability comparison</div>
  <p><strong>Without pipe</strong> — nested calls, read inside-out:</p>
  <pre class="gxd-code-raw">emit(replace(trim(lowercase(ctx.text)), "bad", "***"));</pre>
  <p><strong>With pipe</strong> — reads in execution order:</p>
  <pre class="gxd-code-raw">ctx.text |> lowercase |> trim |> replace("bad", "***") |> emit;</pre>
</div>
`,

/* ─── BUILT-INS ──────────────────────────────────────────── */
builtins: `
<h1>Built-in Functions</h1>
<p>Gravitix includes a rich standard library. All built-in functions are always available — no imports needed.</p>

<h2>String functions</h2>

<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Signature</span><span>Returns</span><span>Description</span></div>
  <div class="gxd-type-row"><code>len(s: str) -> int</code><span>int</span><span>Number of characters</span></div>
  <div class="gxd-type-row"><code>trim(s: str) -> str</code><span>str</span><span>Remove leading/trailing whitespace</span></div>
  <div class="gxd-type-row"><code>lowercase(s: str) -> str</code><span>str</span><span>Convert to lowercase</span></div>
  <div class="gxd-type-row"><code>uppercase(s: str) -> str</code><span>str</span><span>Convert to uppercase</span></div>
  <div class="gxd-type-row"><code>contains(s: str, sub: str) -> bool</code><span>bool</span><span>Check if substring exists</span></div>
  <div class="gxd-type-row"><code>split(s: str, sep: str) -> list&lt;str&gt;</code><span>list&lt;str&gt;</span><span>Split string by separator</span></div>
  <div class="gxd-type-row"><code>replace(s: str, from: str, to: str) -> str</code><span>str</span><span>Replace all occurrences</span></div>
  <div class="gxd-type-row"><code>sanitize(s: str) -> str</code><span>str</span><span>Escape HTML special characters</span></div>
</div>

<pre class="gxd-code-raw">len("hello")                   // → 5
trim("  hi  ")                 // → "hi"
lowercase("HELLO")             // → "hello"
uppercase("hello")             // → "HELLO"
contains("hello world", "world")   // → true
split("a,b,c", ",")           // → ["a", "b", "c"]
replace("foo bar", "bar","baz")    // → "foo baz"
sanitize("&lt;script&gt;")           // → "&amp;lt;script&amp;gt;"</pre>

<h2>Math functions</h2>

<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Signature</span><span>Description</span></div>
  <div class="gxd-type-row"><code>abs(n) -> int|float</code><span>Absolute value</span></div>
  <div class="gxd-type-row"><code>min(a, b) -> int|float</code><span>Smaller of two values</span></div>
  <div class="gxd-type-row"><code>max(a, b) -> int|float</code><span>Larger of two values</span></div>
  <div class="gxd-type-row"><code>floor(f: float) -> int</code><span>Round down to integer</span></div>
  <div class="gxd-type-row"><code>ceil(f: float) -> int</code><span>Round up to integer</span></div>
  <div class="gxd-type-row"><code>round(f: float) -> int</code><span>Round to nearest integer</span></div>
  <div class="gxd-type-row"><code>sqrt(f: float) -> float</code><span>Square root</span></div>
</div>

<pre class="gxd-code-raw">abs(-42)       // → 42
abs(3.14)      // → 3.14
min(3, 7)      // → 3
max(3, 7)      // → 7
floor(3.9)     // → 3
ceil(3.1)      // → 4
round(3.5)     // → 4
sqrt(16.0)     // → 4.0</pre>

<h2>List functions</h2>

<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Signature</span><span>Description</span></div>
  <div class="gxd-type-row"><code>len(list) -> int</code><span>Number of elements</span></div>
  <div class="gxd-type-row"><code>push(list, val)</code><span>Append value to end</span></div>
  <div class="gxd-type-row"><code>pop(list) -> T</code><span>Remove and return last element</span></div>
  <div class="gxd-type-row"><code>reverse(list) -> list&lt;T&gt;</code><span>Return reversed copy</span></div>
  <div class="gxd-type-row"><code>range(start: int, end: int) -> list&lt;int&gt;</code><span>Integer sequence [start, end)</span></div>
</div>

<pre class="gxd-code-raw">let nums = [3, 1, 4, 1, 5];
len(nums)           // → 5
push(nums, 9);      // nums = [3,1,4,1,5,9]
pop(nums)           // → 9, nums = [3,1,4,1,5]
reverse(nums)       // → [5,1,4,1,3]
range(1, 6)         // → [1,2,3,4,5]</pre>

<h2>Type conversion</h2>

<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Signature</span><span>Description</span></div>
  <div class="gxd-type-row"><code>int(x) -> int</code><span>Convert to integer (truncates float, parses str)</span></div>
  <div class="gxd-type-row"><code>float(x) -> float</code><span>Convert to float</span></div>
  <div class="gxd-type-row"><code>str(x) -> str</code><span>Convert to string representation</span></div>
  <div class="gxd-type-row"><code>bool(x) -> bool</code><span>Convert to boolean (0/""/null = false)</span></div>
</div>

<pre class="gxd-code-raw">int("42")        // → 42
int(3.9)         // → 3
float("3.14")    // → 3.14
str(42)          // → "42"
str(true)        // → "true"
bool(0)          // → false
bool(1)          // → true
bool("")         // → false
bool("hello")    // → true</pre>

<h2>Extended math</h2>

<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Signature</span><span>Description</span></div>
  <div class="gxd-type-row"><code>pow(base, exp) -> float</code><span>Raise <code>base</code> to the power of <code>exp</code></span></div>
  <div class="gxd-type-row"><code>random(max: int) -> int</code><span>Random integer in range <code>[0, max)</code></span></div>
  <div class="gxd-type-row"><code>format_number(n) -> str</code><span>Format number with thousands separator (1000 → "1,000")</span></div>
  <div class="gxd-type-row"><code>pad_left(s, width, pad?) -> str</code><span>Left-pad string to given width (default pad char is space)</span></div>
</div>

<pre class="gxd-code-raw">pow(2, 10)              // → 1024.0
pow(3, 3)               // → 27.0
random(6)               // → 0, 1, 2, 3, 4, or 5 (like a die roll)
random(100)             // → random integer 0..99

format_number(1234567)  // → "1,234,567"
emit "Balance: {format_number(state.coins)} coins";

pad_left("7", 3, "0")  // → "007"
pad_left("hi", 5)      // → "   hi"</pre>

<h2>List methods (dot notation)</h2>
<p>Lists support method-call syntax in addition to standalone functions:</p>

<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Method</span><span>Description</span></div>
  <div class="gxd-type-row"><code>list.len() -> int</code><span>Number of elements</span></div>
  <div class="gxd-type-row"><code>list.push(val)</code><span>Append element to end</span></div>
  <div class="gxd-type-row"><code>list.pop() -> T</code><span>Remove and return last element</span></div>
  <div class="gxd-type-row"><code>list.first() -> T</code><span>First element (or null if empty)</span></div>
  <div class="gxd-type-row"><code>list.last() -> T</code><span>Last element (or null if empty)</span></div>
  <div class="gxd-type-row"><code>list.contains(val) -> bool</code><span>Check if value is in the list</span></div>
  <div class="gxd-type-row"><code>list.join(sep) -> str</code><span>Join all elements with separator</span></div>
</div>

<pre class="gxd-code-raw">let tags = ["rust", "go", "python"];

tags.len()               // → 3
tags.push("gravitix");   // tags = ["rust","go","python","gravitix"]
tags.first()             // → "rust"
tags.last()              // → "gravitix"
tags.contains("go")      // → true
tags.join(", ")          // → "rust, go, python, gravitix"

// join is also available as a standalone function:
join(tags, " | ")        // → "rust | go | python | gravitix"</pre>

<h2>Map methods (dot notation)</h2>

<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Method</span><span>Description</span></div>
  <div class="gxd-type-row"><code>map.len() -> int</code><span>Number of entries</span></div>
  <div class="gxd-type-row"><code>map.has(key) -> bool</code><span>True if key exists</span></div>
  <div class="gxd-type-row"><code>map.keys() -> list</code><span>List of all keys</span></div>
  <div class="gxd-type-row"><code>map.values() -> list</code><span>List of all values</span></div>
  <div class="gxd-type-row"><code>map.remove(key)</code><span>Delete an entry by key</span></div>
</div>

<pre class="gxd-code-raw">let scores: map&lt;str, int&gt; = {};
scores["Alice"] = 95;
scores["Bob"]   = 80;

scores.len()             // → 2
scores.has("Alice")      // → true
scores.has("Charlie")    // → false
scores.keys()            // → ["Alice", "Bob"]
scores.values()          // → [95, 80]
scores.remove("Bob");
scores.len()             // → 1</pre>

<h2>Type inspection</h2>

<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Signature</span><span>Description</span></div>
  <div class="gxd-type-row"><code>type_of(x) -> str</code><span>Return the type name as a string</span></div>
  <div class="gxd-type-row"><code>is_null(x) -> bool</code><span>True if value is null</span></div>
  <div class="gxd-type-row"><code>is_int(x) -> bool</code><span>True if value is an integer</span></div>
  <div class="gxd-type-row"><code>is_float(x) -> bool</code><span>True if value is a float</span></div>
  <div class="gxd-type-row"><code>is_str(x) -> bool</code><span>True if value is a string</span></div>
  <div class="gxd-type-row"><code>is_bool(x) -> bool</code><span>True if value is a boolean</span></div>
  <div class="gxd-type-row"><code>is_list(x) -> bool</code><span>True if value is a list</span></div>
  <div class="gxd-type-row"><code>is_map(x) -> bool</code><span>True if value is a map</span></div>
</div>

<pre class="gxd-code-raw">type_of(42)          // → "int"
type_of(3.14)        // → "float"
type_of("hello")     // → "str"
type_of(true)        // → "bool"
type_of([1,2,3])     // → "list"
type_of({})          // → "map"
type_of(null)        // → "null"

// Useful for validating user input:
let reply = wait msg;
if is_null(reply) {
    emit "No reply received.";
    return;
}</pre>

<h2>Environment variables</h2>
<p>Read values from the OS environment — useful for secrets like API keys:</p>

<pre class="gxd-code-raw">let api_key = env("MY_API_KEY");
let db_url  = env("DATABASE_URL");

if is_null(api_key) {
    emit "Error: MY_API_KEY is not set";
    return;
}
emit "Key loaded ({len(api_key)} chars)";</pre>

<div class="gxd-callout gxd-callout-orange">
  <div class="gxd-callout-title">⚠️ Never hardcode secrets</div>
  <p>Do not write API keys or tokens directly in your <code>.grav</code> file. Use <code>env("KEY_NAME")</code> and set the variable in your deployment environment.</p>
</div>

<h2>Debug output</h2>
<p>These functions print to the server console — invisible to users, useful during development:</p>

<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Signature</span><span>Description</span></div>
  <div class="gxd-type-row"><code>print(...) -> void</code><span>Print to standard output</span></div>
  <div class="gxd-type-row"><code>log(...) -> void</code><span>Print to stderr with <code>[gravitix]</code> prefix</span></div>
</div>

<pre class="gxd-code-raw">print("Debug: user id =", ctx.user_id);
print("State:", state.counter);

log("Handler /start triggered");
log("User:", ctx.first_name, "id:", ctx.user_id);

// print/log accept any number of arguments of any type:
print(42, true, [1,2,3], "hello");</pre>

<h2>Time functions</h2>

<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Signature</span><span>Description</span></div>
  <div class="gxd-type-row"><code>now_unix() -> int</code><span>Current time as Unix timestamp (seconds)</span></div>
  <div class="gxd-type-row"><code>now_str() -> str</code><span>Current time as human-readable UTC string</span></div>
</div>

<pre class="gxd-code-raw">let ts = now_unix();     // e.g., 1711234567
let dt = now_str();      // e.g., "2024-03-24 10:15:30"

emit "Server time: {now_str()}";</pre>
`,

/* ─── EXAMPLES ───────────────────────────────────────────── */
examples: `
<h1>Complete Examples</h1>
<p>Full, working bots illustrating common patterns.</p>

<h2>1. Echo Bot</h2>
<p>The simplest useful bot — repeats everything the user says.</p>

<pre class="gxd-code-raw">on /start {
    emit "Hello, {ctx.first_name}! 👋";
    emit "I will echo everything you send me.";
}

on /help {
    emit "Just send me any message and I'll repeat it!";
}

on msg {
    emit "You said:\\n{ctx.text}";
}</pre>

<h2>2. Counter Bot</h2>
<p>A simple bot that counts button presses per user.</p>

<pre class="gxd-code-raw">state {
    counts: map&lt;int, int&gt; = {},
}

on /start {
    state.counts[ctx.user_id] = 0;
    emit "Counter started! Use /click to increment.";
}

on /click {
    let current = state.counts[ctx.user_id];
    if current == null { current = 0; }
    state.counts[ctx.user_id] = current + 1;
    emit "Count: {current + 1} 🔢";
}

on /score {
    let count = state.counts[ctx.user_id];
    if count == null { count = 0; }
    emit "Your count: {count}";
}

on /reset {
    state.counts[ctx.user_id] = 0;
    emit "Reset to 0!";
}</pre>

<h2>3. Quiz Bot</h2>
<p>A multiple-choice quiz with scoring.</p>

<pre class="gxd-code-raw">state {
    scores:    map&lt;int, int&gt; = {},
    in_quiz:   map&lt;int, bool&gt; = {},
}

flow quiz {
    state.scores[ctx.user_id] = 0;

    // Question 1
    emit "Q1: What is 2 + 2?\\na) 3\\nb) 4\\nc) 5";
    let a1 = wait msg;
    if a1 == "b" || a1 == "4" {
        state.scores[ctx.user_id] += 1;
        emit "✅ Correct!";
    } else {
        emit "❌ Wrong! Answer was b) 4";
    }

    // Question 2
    emit "Q2: Which language inspired Gravitix?\\na) Python\\nb) JavaScript\\nc) Rust";
    let a2 = wait msg;
    if a2 == "c" || a2 == "Rust" || lowercase(a2) == "rust" {
        state.scores[ctx.user_id] += 1;
        emit "✅ Correct!";
    } else {
        emit "❌ Wrong! Answer was c) Rust";
    }

    // Result
    let final_score = state.scores[ctx.user_id];
    emit "Quiz complete! Your score: {final_score}/2";
    if final_score == 2 { emit "🏆 Perfect score!"; }
    elif final_score == 1 { emit "👍 Not bad!"; }
    else { emit "📚 Keep studying!"; }
}

on /quiz {
    emit "Starting quiz… Answer with the letter or the word.";
    run flow quiz;
}

on /start {
    emit "Welcome to QuizBot! Use /quiz to start.";
}</pre>

<h2>4. Todo List Bot</h2>
<p>A personal task manager per user.</p>

<pre class="gxd-code-raw">state {
    todos: map&lt;int, list&lt;str&gt;&gt; = {},
}

fn ensure_list(user_id: int) {
    if state.todos[user_id] == null {
        state.todos[user_id] = [];
    }
}

on /start {
    emit "📝 Todo Bot\\n/add &lt;task&gt; — add a task\\n/list — show tasks\\n/done &lt;n&gt; — remove task";
}

on /add {
    ensure_list(ctx.user_id);
    let parts = split(ctx.text, " ");
    if len(parts) < 2 {
        emit "Usage: /add &lt;task description&gt;";
        return;
    }
    // Everything after "/add "
    let task = ctx.text;
    push(state.todos[ctx.user_id], task);
    emit "✅ Added: {task}";
}

on /list {
    ensure_list(ctx.user_id);
    let tasks = state.todos[ctx.user_id];
    if len(tasks) == 0 {
        emit "Your list is empty. Add tasks with /add";
        return;
    }
    let out = "📋 Your tasks:\\n";
    for i in range(0, len(tasks)) {
        out = out + "{i+1}. {tasks[i]}\\n";
    }
    emit out;
}

on /clear guard ctx.user_id != null {
    state.todos[ctx.user_id] = [];
    emit "🗑️ All tasks cleared.";
}</pre>

<h2>5. Registration Flow Bot</h2>
<p>Collects user profile through a conversation.</p>

<pre class="gxd-code-raw">state {
    profiles: map&lt;int, str&gt; = {},
}

flow register {
    emit "Let's create your profile!";

    emit "Step 1/3: What's your display name?";
    let name = wait msg;
    if len(trim(name)) == 0 {
        emit "Name cannot be empty. Starting over…";
        return;
    }

    emit "Step 2/3: How old are you?";
    let age_raw = wait msg;
    let age = int(age_raw);
    if age < 1 || age > 120 {
        emit "Invalid age. Starting over…";
        return;
    }

    emit "Step 3/3: What's your favourite language?";
    let lang = wait msg;

    // Build a simple CSV profile string
    let profile = "{name}|{age}|{lang}";
    state.profiles[ctx.user_id] = profile;

    emit "✅ Profile saved!\\n👤 {name}, {age} years old, loves {lang}.";
    emit "Use /profile to view it anytime.";
}

on /register {
    if state.profiles[ctx.user_id] != null {
        emit "You already have a profile! Use /profile to view it.";
        return;
    }
    run flow register;
}

on /profile {
    let p = state.profiles[ctx.user_id];
    if p == null {
        emit "No profile found. Use /register to create one.";
        return;
    }
    let parts = split(p, "|");
    emit "Your profile:\\n👤 Name: {parts[0]}\\n🎂 Age: {parts[1]}\\n💻 Favourite: {parts[2]}";
}

on /start {
    emit "Welcome! Use /register to set up your profile.";
}</pre>
`,

/* ─── BEST PRACTICES ─────────────────────────────────────── */
bestpractices: `
<h1>Best Practices</h1>
<p>Patterns and habits that make your Gravitix bots more reliable, readable, and maintainable.</p>

<h2>1. Always handle the unknown</h2>
<p>Every bot should have a fallback <code>on msg</code> handler so users always get a response:</p>

<pre class="gxd-code-raw">on msg {
    emit "Sorry, I don't understand that.\\nTry /help for a list of commands.";
}</pre>

<h2>2. Validate user input</h2>
<p>Never assume what the user sent is valid:</p>

<pre class="gxd-code-raw">on /setage {
    let raw = ctx.text;
    let age = int(raw);
    if age < 1 || age > 130 {
        emit "Please enter a valid age between 1 and 130.";
        return;
    }
    state.age = age;
    emit "Age set to {age}.";
}</pre>

<h2>3. Use guards instead of if-chains for permissions</h2>
<pre class="gxd-code-raw">// ❌ Verbose
on /admin {
    if !ctx.is_admin {
        emit "No access.";
        return;
    }
    emit "Admin panel";
}

// ✅ Clean
on /admin guard ctx.is_admin { emit "Admin panel"; }
on /admin { emit "No access."; }</pre>

<h2>4. Extract logic into functions</h2>
<p>Keep handlers short. Move complex logic to named functions:</p>

<pre class="gxd-code-raw">fn format_leaderboard(scores: map&lt;int, int&gt;) -> str {
    let out = "🏆 Leaderboard:\\n";
    // ... build the string
    return out;
}

on /top {
    emit format_leaderboard(state.scores);
}</pre>

<h2>5. Use early return to reduce nesting</h2>
<pre class="gxd-code-raw">// ❌ Deeply nested
on /buy {
    if is_registered {
        if has_balance {
            if item_in_stock {
                // actual logic
            } else { emit "Out of stock"; }
        } else { emit "Insufficient balance"; }
    } else { emit "Please register"; }
}

// ✅ Flat with early returns
on /buy {
    if !is_registered { emit "Please register first."; return; }
    if !has_balance    { emit "Insufficient balance.";  return; }
    if !item_in_stock  { emit "Out of stock.";          return; }
    // actual logic here
    emit "Purchase complete!";
}</pre>

<h2>6. Name things clearly</h2>
<pre class="gxd-code-raw">// ❌ Cryptic
let x = state.m[ctx.u];

// ✅ Readable
let message_count = state.messages[ctx.user_id];</pre>

<h2>7. Reset state carefully</h2>
<p>Always guard destructive operations:</p>

<pre class="gxd-code-raw">on /nuke guard ctx.is_admin {
    state.data = {};
    state.users = [];
    emit "All data cleared.";
}

on /nuke {
    emit "Only admins can do that.";
}</pre>

<h2>8. Use state to prevent spam</h2>
<pre class="gxd-code-raw">state {
    last_action: map&lt;int, int&gt; = {},
}

fn rate_limit(user_id: int, min_interval: int) -> bool {
    let last = state.last_action[user_id];
    let now  = now_unix();
    if last != null && (now - last) < min_interval {
        return false;
    }
    state.last_action[user_id] = now;
    return true;
}

on /expensive_operation {
    if !rate_limit(ctx.user_id, 60) {
        emit "Please wait before using this command again.";
        return;
    }
    // do the expensive thing
}</pre>

<div class="gxd-callout gxd-callout-blue">
  <div class="gxd-callout-title">🎓 Keep learning</div>
  <p>The best way to learn Gravitix is to build. Start with a simple echo bot, then add state, then add flows. Each new concept you learn opens up more possibilities.</p>
</div>
`,

/* ─── COMPLEX NUMBERS ───────────────────────────────────── */
complex_type: `
<h1>Complex Numbers</h1>
<p class="gxd-lead">Gravitix has a native <code>complex</code> type — a pair of 64-bit floats representing the real and imaginary parts. You can use it directly without any imports.</p>

<h2>What is a complex number?</h2>
<p>A complex number has the form <strong>a + bi</strong>, where <em>a</em> is the real part and <em>b</em> is the imaginary part. <em>i</em> is the imaginary unit defined by <em>i² = −1</em>. Complex numbers extend the real line to a plane, allowing solutions to equations like <em>x² + 1 = 0</em> that have no real answer.</p>
<p>In Gravitix you write imaginary literals with the <code>i</code> suffix:</p>
<pre class="gxd-code-raw">let z1 = 3.0 + 4.0i;   // real=3, imag=4
let z2 = 2.0 - 1.0i;   // real=2, imag=-1
let pure_imag = 5i;     // real=0, imag=5  (int suffix also works)
let real_only = 7.0;    // treated as 7+0i in complex context</pre>

<h2>Arithmetic on complex numbers</h2>
<p>All four basic operations work on complex values directly. Gravitix follows standard complex arithmetic rules:</p>
<ul>
  <li><strong>Addition:</strong> (a+bi) + (c+di) = (a+c) + (b+d)i</li>
  <li><strong>Subtraction:</strong> (a+bi) − (c+di) = (a−c) + (b−d)i</li>
  <li><strong>Multiplication:</strong> (a+bi)(c+di) = (ac−bd) + (ad+bc)i</li>
  <li><strong>Division:</strong> (a+bi)/(c+di) = [(ac+bd)/(c²+d²)] + [(bc−ad)/(c²+d²)]i</li>
  <li><strong>Power:</strong> z**n uses De Moivre's formula for integer n</li>
</ul>
<pre class="gxd-code-raw">let a = 3.0 + 4.0i;
let b = 1.0 - 2.0i;

let s = a + b;    // → 4 + 2i
let d = a - b;    // → 2 + 6i
let p = a * b;    // → (3·1 − 4·(−2)) + (3·(−2) + 4·1)i = 11 − 2i
let q = a / b;    // → (3+4i)/(1−2i) = −1 + 2i</pre>

<h2>Built-in complex functions</h2>
<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Function</span><span>Returns</span><span>Description</span></div>
  <div class="gxd-type-row"><code>complex(re, im)</code><span>complex</span><span>Construct from two floats</span></div>
  <div class="gxd-type-row"><code>re(z)</code><span>float</span><span>Real part of z</span></div>
  <div class="gxd-type-row"><code>im(z)</code><span>float</span><span>Imaginary part of z</span></div>
  <div class="gxd-type-row"><code>conj(z)</code><span>complex</span><span>Complex conjugate: a+bi → a−bi</span></div>
  <div class="gxd-type-row"><code>cabs(z)</code><span>float</span><span>Modulus (absolute value): √(a²+b²)</span></div>
  <div class="gxd-type-row"><code>arg(z)</code><span>float</span><span>Argument (angle in radians): atan2(b, a)</span></div>
  <div class="gxd-type-row"><code>polar(r, theta)</code><span>complex</span><span>From polar form: r·e^(iθ) = r·cos θ + ir·sin θ</span></div>
  <div class="gxd-type-row"><code>cexp(z)</code><span>complex</span><span>e^z = e^a·(cos b + i·sin b)</span></div>
  <div class="gxd-type-row"><code>clog(z)</code><span>complex</span><span>Principal logarithm: ln|z| + i·arg(z)</span></div>
  <div class="gxd-type-row"><code>csqrt(z)</code><span>complex</span><span>Principal square root</span></div>
  <div class="gxd-type-row"><code>cpow(z, w)</code><span>complex</span><span>z^w = e^(w·ln z)</span></div>
  <div class="gxd-type-row"><code>csin(z) / ccos(z) / ctan(z)</code><span>complex</span><span>Trig functions extended to complex plane</span></div>
  <div class="gxd-type-row"><code>mobius(z,a,b,c,d)</code><span>complex</span><span>Möbius transform: (az+b)/(cz+d)</span></div>
</div>

<pre class="gxd-code-raw">let z = 3.0 + 4.0i;

re(z)         // → 3.0
im(z)         // → 4.0
conj(z)       // → 3 − 4i
cabs(z)       // → 5.0  (because √(9+16) = 5)
arg(z)        // → 0.9272952... radians (~53.13°)

// Euler's formula: e^(iπ) = −1
let euler = cexp(complex(0.0, PI));
// → complex(−1.0, ~0.0)  — the most beautiful formula in math

// Polar form: represent z by magnitude and angle
let mag = cabs(z);       // 5.0
let phi = arg(z);        // ~0.927 rad
polar(mag, phi);         // → 3 + 4i  (round-trip)

// Principal square root of −1 is i
csqrt(complex(-1.0, 0.0)); // → 0 + 1i</pre>

<div class="gxd-callout gxd-callout-purple">
  <div class="gxd-callout-title">🌀 Why complex numbers in a bot language?</div>
  <p>Signal processing (audio analysis, FFT), fractal generation (Mandelbrot set), physics simulations, electrical impedance calculations, and quantum computing all require complex arithmetic. Gravitix lets you run these calculations right inside a Vortex bot without external libraries.</p>
</div>
`,

/* ─── BITWISE ───────────────────────────────────────────── */
bitwise: `
<h1>Bitwise Operators</h1>
<p class="gxd-lead">Bitwise operators work directly on the binary representation of integers. Each integer is a 64-bit signed value; bitwise ops treat it as a sequence of 64 bits.</p>

<h2>Available operators</h2>
<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Operator</span><span>Name</span><span>Example</span><span>Result</span></div>
  <div class="gxd-type-row"><code>&amp;</code><span>Bitwise AND</span><code>0b1010 &amp; 0b1100</code><span>0b1000 (8)</span></div>
  <div class="gxd-type-row"><code>|</code><span>Bitwise OR</span><code>0b1010 | 0b1100</code><span>0b1110 (14)</span></div>
  <div class="gxd-type-row"><code>^</code><span>Bitwise XOR</span><code>0b1010 ^ 0b1100</code><span>0b0110 (6)</span></div>
  <div class="gxd-type-row"><code>~</code><span>Bitwise NOT</span><code>~0</code><span>−1 (all bits set)</span></div>
  <div class="gxd-type-row"><code>&lt;&lt;</code><span>Left shift</span><code>1 &lt;&lt; 4</code><span>16</span></div>
  <div class="gxd-type-row"><code>&gt;&gt;</code><span>Right shift</span><code>256 &gt;&gt; 3</code><span>32</span></div>
</div>

<h2>Compound assignment</h2>
<pre class="gxd-code-raw">let flags = 0;
flags |= 0b0001;   // set bit 0  → 1
flags |= 0b0100;   // set bit 2  → 5
flags &amp;= ~0b0001;  // clear bit 0 → 4
flags ^= 0b0110;   // toggle bits 1,2 → 2</pre>

<h2>Practical use cases</h2>
<pre class="gxd-code-raw">// Permission flags — each bit is a permission
let PERM_READ    = 1;   // 001
let PERM_WRITE   = 2;   // 010
let PERM_ADMIN   = 4;   // 100

fn has_perm(user_flags: int, perm: int) -> bool {
    return (user_flags &amp; perm) != 0;
}

let alice = PERM_READ | PERM_WRITE;  // 011 = 3
has_perm(alice, PERM_READ)    // → true
has_perm(alice, PERM_ADMIN)   // → false

// Fast multiply / divide by power of 2
let x = 5;
x &lt;&lt; 3;   // 5 × 8 = 40  (faster than multiplication)
x &gt;&gt; 1;   // 5 ÷ 2 = 2   (integer division by 2)

// Check if number is even
fn is_even(n: int) -> bool { return (n &amp; 1) == 0; }

// XOR swap (no temp variable)
let a = 10; let b = 20;
a = a ^ b;  b = a ^ b;  a = a ^ b;
// now a=20, b=10</pre>
`,

/* ─── ERROR HANDLING ────────────────────────────────────── */
error: `
<h1>Error Handling</h1>
<p class="gxd-lead">Gravitix provides structured error handling with <code>try / catch / finally</code> blocks, similar to many modern languages but with a clean, minimal syntax.</p>

<h2>Basic try / catch</h2>
<p>Wrap any code that might fail in a <code>try</code> block. If an error is thrown — either by Gravitix runtime or explicitly by your code — execution jumps to the <code>catch</code> block. The caught value is bound to the variable you name after <code>catch</code>.</p>
<pre class="gxd-code-raw">try {
    let n = int(ctx.text);   // fails if user sent "hello"
    emit "Number squared: {n * n}";
} catch e {
    emit "That's not a number. Error: {e}";
}</pre>

<h2>The finally block</h2>
<p><code>finally</code> runs unconditionally — whether the try succeeded or the catch handled an error. Use it to release resources, log, or send a completion message.</p>
<pre class="gxd-code-raw">try {
    let result = call_external_api(ctx.text);
    emit "Result: {result}";
} catch e {
    emit "API call failed: {e}";
} finally {
    emit "Request completed.";   // always runs
}</pre>

<h2>Throwing errors explicitly</h2>
<pre class="gxd-code-raw">fn divide(a: float, b: float) -> float {
    if b == 0.0 {
        throw "Division by zero";
    }
    return a / b;
}

on /divide {
    try {
        let parts = split(ctx.text, " ");
        let a = float(parts[0]);
        let b = float(parts[1]);
        emit "Result: {divide(a, b)}";
    } catch e {
        emit "Error: {e}";
    }
}</pre>

<h2>Nested try blocks</h2>
<pre class="gxd-code-raw">try {
    let data = json_parse(ctx.text);
    try {
        let value = data["key"];
        emit "Value: {value}";
    } catch inner {
        emit "Missing key in JSON.";
    }
} catch outer {
    emit "Invalid JSON format.";
}</pre>

<div class="gxd-callout gxd-callout-orange">
  <div class="gxd-callout-title">⚠️ When to use try/catch</div>
  <p>Use error handling for operations that depend on external input: parsing user text, calling APIs, reading environment variables, or doing complex math where domain errors (sqrt of negative, log of zero) are possible. For internal logic errors, prefer <code>guard</code> clauses and early returns.</p>
</div>
`,

/* ─── STRUCTS & ENUMS ───────────────────────────────────── */
structs: `
<h1>Structs &amp; Enums</h1>
<p class="gxd-lead">Structs let you group related data under a named type. Enums define a closed set of variants, optionally carrying data. Together they enable expressive domain modeling.</p>

<h2>Defining a struct</h2>
<pre class="gxd-code-raw">struct User {
    id:    int,
    name:  str,
    score: int,
    active: bool,
}

// Create an instance
let u = User { id: 1, name: "Alice", score: 42, active: true };

// Access fields with dot notation
emit "Hello, {u.name}! Your score: {u.score}";

// Mutate fields
u.score += 10;</pre>

<h2>Methods on structs (impl blocks)</h2>
<p>Use <code>impl TypeName { ... }</code> to attach methods to a struct. Inside a method, <code>self</code> refers to the instance.</p>
<pre class="gxd-code-raw">impl User {
    fn greet(self) -> str {
        return "Hi, I'm {self.name} with score {self.score}";
    }

    fn promote(self) {
        self.score *= 2;
        emit "{self.name} promoted! New score: {self.score}";
    }

    fn is_active(self) -> bool {
        return self.active &amp;&amp; self.score > 0;
    }
}

u.greet()    // → "Hi, I'm Alice with score 52"
u.promote()  // emits "Alice promoted! New score: 104"</pre>

<h2>Enums</h2>
<p>Enums define a type that can be exactly one of several variants. Variants can be plain (like constants) or carry data.</p>
<pre class="gxd-code-raw">enum Status {
    Pending,
    Active,
    Banned(str),    // carries a reason string
}

let s1 = Status.Active;
let s2 = Status.Banned("spam");

match s2 {
    Status.Pending       => emit "Awaiting approval",
    Status.Active        => emit "User is active",
    Status.Banned(reason) => emit "Banned: {reason}",
}</pre>

<h2>Enums with numeric data</h2>
<pre class="gxd-code-raw">enum Shape {
    Circle(float),          // radius
    Rectangle(float, float), // width, height
    Triangle(float, float, float), // three sides
}

fn area(s: Shape) -> float {
    match s {
        Shape.Circle(r)       => return PI * r * r,
        Shape.Rectangle(w, h) => return w * h,
        Shape.Triangle(a,b,c) => {
            // Heron's formula
            let p = (a + b + c) / 2.0;
            return sqrt(p * (p-a) * (p-b) * (p-c));
        },
    }
}

area(Shape.Circle(5.0))           // → 78.539...
area(Shape.Rectangle(4.0, 6.0))   // → 24.0</pre>
`,

/* ─── MATH CORE ─────────────────────────────────────────── */
math_core: `
<h1>Core Mathematics</h1>
<p class="gxd-lead">Gravitix ships a comprehensive math library with ~180 functions spanning basic arithmetic, trigonometry, logarithms, and advanced helpers. All functions work on <code>int</code> and <code>float</code> values unless noted.</p>

<h2>Mathematical constants</h2>
<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Constant</span><span>Value</span><span>Description</span></div>
  <div class="gxd-type-row"><code>PI</code><span>3.14159265358979…</span><span>Ratio of circle circumference to diameter</span></div>
  <div class="gxd-type-row"><code>E</code><span>2.71828182845904…</span><span>Euler's number, base of natural logarithm</span></div>
  <div class="gxd-type-row"><code>TAU</code><span>6.28318530717958…</span><span>2π — full circle in radians</span></div>
  <div class="gxd-type-row"><code>PHI</code><span>1.61803398874989…</span><span>Golden ratio φ = (1+√5)/2</span></div>
  <div class="gxd-type-row"><code>EULER_GAMMA</code><span>0.57721566490153…</span><span>Euler–Mascheroni constant γ</span></div>
  <div class="gxd-type-row"><code>INF</code><span>∞</span><span>Positive infinity</span></div>
  <div class="gxd-type-row"><code>NAN</code><span>NaN</span><span>Not-a-Number (result of 0/0, etc.)</span></div>
</div>

<h2>Trigonometric functions</h2>
<p>All trig functions expect angles in <strong>radians</strong>. Use <code>radians(deg)</code> to convert from degrees.</p>
<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Function</span><span>Description</span></div>
  <div class="gxd-type-row"><code>sin(x)</code><span>Sine. sin(π/2) = 1, sin(π) ≈ 0</span></div>
  <div class="gxd-type-row"><code>cos(x)</code><span>Cosine. cos(0) = 1, cos(π) = −1</span></div>
  <div class="gxd-type-row"><code>tan(x)</code><span>Tangent = sin/cos. Undefined at π/2 + nπ</span></div>
  <div class="gxd-type-row"><code>asin(x)</code><span>Arcsine. Domain [−1, 1], range [−π/2, π/2]</span></div>
  <div class="gxd-type-row"><code>acos(x)</code><span>Arccosine. Domain [−1, 1], range [0, π]</span></div>
  <div class="gxd-type-row"><code>atan(x)</code><span>Arctangent. Range (−π/2, π/2)</span></div>
  <div class="gxd-type-row"><code>atan2(y, x)</code><span>Angle of vector (x,y) from positive x-axis. Range (−π, π]. Handles x=0.</span></div>
  <div class="gxd-type-row"><code>sinh(x) / cosh(x) / tanh(x)</code><span>Hyperbolic functions: sinh(x)=(eˣ−e⁻ˣ)/2, etc.</span></div>
  <div class="gxd-type-row"><code>asinh(x) / acosh(x) / atanh(x)</code><span>Inverse hyperbolic functions</span></div>
  <div class="gxd-type-row"><code>degrees(r)</code><span>Convert radians to degrees: r × 180/π</span></div>
  <div class="gxd-type-row"><code>radians(d)</code><span>Convert degrees to radians: d × π/180</span></div>
</div>

<pre class="gxd-code-raw">sin(PI / 2)          // → 1.0
cos(PI)              // → −1.0
tan(radians(45.0))   // → 1.0

// Law of cosines: c² = a² + b² − 2ab·cos(C)
fn law_of_cosines(a: float, b: float, angle_c: float) -> float {
    let C = radians(angle_c);
    return sqrt(a**2 + b**2 - 2.0 * a * b * cos(C));
}
law_of_cosines(3.0, 4.0, 90.0)  // → 5.0  (right triangle!)

// Pendulum period: T = 2π√(L/g)
fn pendulum(length_m: float) -> float {
    return TAU * sqrt(length_m / 9.81);
}</pre>

<h2>Logarithm &amp; Exponential</h2>
<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Function</span><span>Description</span></div>
  <div class="gxd-type-row"><code>ln(x)</code><span>Natural log (base e). ln(e) = 1, ln(1) = 0. Domain x &gt; 0.</span></div>
  <div class="gxd-type-row"><code>log2(x)</code><span>Binary log. log₂(1024) = 10. Number of bits needed.</span></div>
  <div class="gxd-type-row"><code>log10(x)</code><span>Common log. log₁₀(1000) = 3. Order of magnitude.</span></div>
  <div class="gxd-type-row"><code>log(x, base)</code><span>Arbitrary base: log_b(x) = ln(x)/ln(b)</span></div>
  <div class="gxd-type-row"><code>exp(x)</code><span>eˣ. exp(1) = 2.71828…</span></div>
  <div class="gxd-type-row"><code>exp2(x)</code><span>2ˣ. exp2(10) = 1024.</span></div>
</div>

<pre class="gxd-code-raw">ln(E)         // → 1.0
ln(1.0)       // → 0.0
log10(1000.0) // → 3.0
log2(1024.0)  // → 10.0
log(81.0, 3.0) // → 4.0  (3⁴=81)

// Compound interest: A = P·e^(rt)
fn compound(principal: float, rate: float, years: float) -> float {
    return principal * exp(rate * years);
}
compound(1000.0, 0.05, 10.0)  // → 1648.72  (5% for 10 years)</pre>

<h2>Rounding &amp; Precision</h2>
<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Function</span><span>Description</span></div>
  <div class="gxd-type-row"><code>floor(x)</code><span>Round down: floor(3.7) = 3, floor(−3.7) = −4</span></div>
  <div class="gxd-type-row"><code>ceil(x)</code><span>Round up: ceil(3.2) = 4, ceil(−3.2) = −3</span></div>
  <div class="gxd-type-row"><code>round(x)</code><span>Round to nearest integer (half away from zero)</span></div>
  <div class="gxd-type-row"><code>trunc(x)</code><span>Truncate toward zero: trunc(3.9) = 3, trunc(−3.9) = −3</span></div>
  <div class="gxd-type-row"><code>fract(x)</code><span>Fractional part: fract(3.7) = 0.7, fract(−3.7) = −0.7</span></div>
  <div class="gxd-type-row"><code>abs(x)</code><span>Absolute value</span></div>
  <div class="gxd-type-row"><code>sign(x)</code><span>−1, 0, or 1 depending on sign</span></div>
  <div class="gxd-type-row"><code>approx_eq(a, b, eps?)</code><span>True if |a−b| &lt; eps (default 1e-9). Safe float comparison.</span></div>
</div>

<h2>Geometry &amp; Interpolation</h2>
<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Function</span><span>Description</span></div>
  <div class="gxd-type-row"><code>sqrt(x)</code><span>Square root. sqrt(2) ≈ 1.41421…</span></div>
  <div class="gxd-type-row"><code>cbrt(x)</code><span>Cube root. cbrt(8) = 2</span></div>
  <div class="gxd-type-row"><code>nroot(x, n)</code><span>n-th root: x^(1/n)</span></div>
  <div class="gxd-type-row"><code>hypot(x, y)</code><span>√(x²+y²) — length of hypotenuse, numerically stable</span></div>
  <div class="gxd-type-row"><code>clamp(x, lo, hi)</code><span>Constrain x to [lo, hi]</span></div>
  <div class="gxd-type-row"><code>lerp(a, b, t)</code><span>Linear interpolation: a + t·(b−a). t=0→a, t=1→b</span></div>
  <div class="gxd-type-row"><code>map_range(x, a, b, c, d)</code><span>Map x from [a,b] to [c,d]</span></div>
</div>

<pre class="gxd-code-raw">hypot(3.0, 4.0)              // → 5.0
clamp(150.0, 0.0, 100.0)     // → 100.0
lerp(0.0, 100.0, 0.25)       // → 25.0
map_range(5.0, 0.0, 10.0, 0.0, 1.0)  // → 0.5  (normalize to [0,1])

// Smooth animation value
fn ease_in_out(t: float) -> float {
    return t * t * (3.0 - 2.0 * t);
}</pre>
`,

/* ─── COMPLEX ANALYSIS ──────────────────────────────────── */
math_complex: `
<h1>Complex Analysis</h1>
<p class="gxd-lead">Complex analysis studies functions of complex variables. It is the foundation of signal processing, fluid dynamics, quantum mechanics, and many areas of pure mathematics. Gravitix gives you the full toolkit.</p>

<h2>The complex plane</h2>
<p>Every complex number z = a + bi can be visualized as a point (a, b) on the <em>Argand plane</em>. The horizontal axis is the real axis, the vertical is the imaginary axis.</p>
<ul>
  <li><strong>Modulus</strong> |z| = √(a²+b²) — distance from origin (cabs)</li>
  <li><strong>Argument</strong> arg(z) = atan2(b, a) — angle from positive real axis</li>
  <li><strong>Polar form</strong> z = |z|·e^(i·arg(z)) = |z|·(cos θ + i·sin θ)</li>
</ul>

<h2>Euler's formula and applications</h2>
<p>One of the most important identities in mathematics: <strong>e^(ix) = cos x + i·sin x</strong>. This means the unit circle in the complex plane is parametrized by angle x.</p>
<pre class="gxd-code-raw">// Rotating a point by angle theta in 2D
// is equivalent to multiplying by e^(i·theta)
fn rotate_2d(x: float, y: float, theta: float) -> list {
    let point = complex(x, y);
    let rotation = cexp(complex(0.0, theta));
    let result = point * rotation;
    return [re(result), im(result)];
}

// Rotate (1, 0) by 90 degrees = π/2 radians
rotate_2d(1.0, 0.0, PI / 2.0)   // → [~0, 1]  (the point (0,1))

// Roots of unity: n-th roots of 1 are e^(2πik/n) for k=0..n-1
fn nth_roots(n: int) -> list {
    let roots = [];
    let k = 0;
    while k < n {
        push(roots, cexp(complex(0.0, TAU * float(k) / float(n))));
        k += 1;
    }
    return roots;
}</pre>

<h2>Analytic functions</h2>
<p>The complex exponential, sine, cosine, and logarithm are extended to the full complex plane. Their Taylor series converge everywhere (or on a disk for log).</p>

<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Function</span><span>Formula</span><span>Notes</span></div>
  <div class="gxd-type-row"><code>cexp(z)</code><span>e^a·(cos b + i·sin b)</span><span>Entire function, never zero</span></div>
  <div class="gxd-type-row"><code>clog(z)</code><span>ln|z| + i·arg(z)</span><span>Principal branch; discontinuous on negative real axis</span></div>
  <div class="gxd-type-row"><code>csin(z)</code><span>(e^(iz) − e^(−iz))/(2i)</span><span>sin(iy) = i·sinh(y)</span></div>
  <div class="gxd-type-row"><code>ccos(z)</code><span>(e^(iz) + e^(−iz))/2</span><span>cos(iy) = cosh(y)</span></div>
  <div class="gxd-type-row"><code>ctan(z)</code><span>csin(z)/ccos(z)</span><span>Poles at z = π/2 + nπ</span></div>
  <div class="gxd-type-row"><code>cpow(z, w)</code><span>e^(w·clog(z))</span><span>Generalizes z^n to complex exponents</span></div>
</div>

<pre class="gxd-code-raw">// Mandelbrot set iteration (z → z² + c)
fn mandelbrot_iter(cx: float, cy: float, max_iter: int) -> int {
    let z = complex(0.0, 0.0);
    let c = complex(cx, cy);
    let i = 0;
    while i < max_iter && cabs(z) < 2.0 {
        z = z * z + c;
        i += 1;
    }
    return i;
}

// Möbius transformation maps circles/lines to circles/lines
// f(z) = (az + b) / (cz + d)
let w = mobius(complex(1.0, 1.0), 1.0, 0.0, 0.0, 1.0);
// with a=1,b=0,c=0,d=1 this is identity: w = z</pre>

<h2>Complex power and logarithm</h2>
<p>For complex z and w, z^w = e^(w·ln z). This allows non-integer and complex exponents, revealing surprising connections:</p>
<pre class="gxd-code-raw">// i^i is a real number!
let ii = cpow(complex(0.0, 1.0), complex(0.0, 1.0));
// = e^(i·ln(i)) = e^(i·(π/2)i) = e^(-π/2) ≈ 0.2078...
re(ii)   // → 0.20787957635...

// (−1)^(1/3) has three cube roots in complex plane
cpow(complex(-1.0, 0.0), complex(1.0/3.0, 0.0))
// principal root ≈ 0.5 + 0.866i</pre>
`,

/* ─── CALCULUS ──────────────────────────────────────────── */
math_calculus: `
<h1>Calculus</h1>
<p class="gxd-lead">Gravitix includes numerical calculus: derivatives and integrals computed on arbitrary functions. All methods are numerical approximations — the accuracy depends on the step size and method used.</p>

<h2>Derivatives</h2>
<p>The <strong>derivative</strong> f'(x) measures how fast f changes at point x. Geometrically it is the slope of the tangent line. Gravitix uses <em>central difference</em> for first derivatives (error O(h²)) and <em>second-order formula</em> for second derivatives.</p>
<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Function</span><span>Formula used</span><span>Description</span></div>
  <div class="gxd-type-row"><code>deriv(f, x)</code><span>(f(x+h)−f(x−h))/(2h)</span><span>First derivative at point x</span></div>
  <div class="gxd-type-row"><code>deriv2(f, x)</code><span>(f(x+h)−2f(x)+f(x−h))/h²</span><span>Second derivative (curvature)</span></div>
  <div class="gxd-type-row"><code>diff(xs, ys)</code><span>(y[i+1]−y[i−1])/(x[i+1]−x[i−1])</span><span>Numerical derivative of data points</span></div>
  <div class="gxd-type-row"><code>gradient_2d(f, x, y)</code><span>[∂f/∂x, ∂f/∂y]</span><span>Gradient vector of f at (x,y)</span></div>
</div>

<pre class="gxd-code-raw">// Derivative of x² is 2x
fn square(x: float) -> float { return x * x; }
deriv(square, 3.0)    // → ~6.0  (exactly 2·3 = 6)

// Second derivative of x² is 2 (constant curvature)
deriv2(square, 5.0)   // → ~2.0

// Velocity from position data
let times = [0.0, 0.1, 0.2, 0.3, 0.4];
let pos   = [0.0, 0.5, 2.0, 4.5, 8.0];  // x = 50t²
let vel   = diff(times, pos);            // velocity at each point
// vel ≈ [5.0, 10.0, 15.0, 20.0, ...]

// Gradient of f(x,y) = x² + y²
fn f(x: float, y: float) -> float { return x*x + y*y; }
gradient_2d(f, 1.0, 2.0)   // → [2.0, 4.0]  (= [2x, 2y])</pre>

<h2>Numerical integration</h2>
<p>An <strong>integral</strong> ∫f(x)dx from a to b is the area under the curve. Gravitix provides three methods with increasing accuracy:</p>
<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Function</span><span>Method</span><span>Error order</span></div>
  <div class="gxd-type-row"><code>integral_trapz(f, a, b, n?)</code><span>Trapezoidal rule</span><span>O(h²), n steps (default 1000)</span></div>
  <div class="gxd-type-row"><code>integral_simpson(f, a, b, n?)</code><span>Simpson's 1/3 rule</span><span>O(h⁴), much more accurate</span></div>
  <div class="gxd-type-row"><code>romberg(f, a, b, depth?)</code><span>Richardson extrapolation</span><span>Exponential convergence</span></div>
</div>

<pre class="gxd-code-raw">fn my_func(x: float) -> float { return x * x; }  // f(x) = x²

// ∫₀¹ x² dx = [x³/3]₀¹ = 1/3 ≈ 0.333...
integral_trapz(my_func, 0.0, 1.0)        // → 0.3333350 (n=1000)
integral_simpson(my_func, 0.0, 1.0)      // → 0.3333333 (more accurate)
romberg(my_func, 0.0, 1.0)               // → 0.3333333333...

// Area of semicircle with radius 1: should be π/2
fn semicircle(x: float) -> float { return sqrt(1.0 - x*x); }
integral_simpson(semicircle, -1.0, 1.0)  // → ~1.5707963 = π/2 ✓

// Expected value: E[X] = ∫ x·p(x) dx over normal distribution
fn normal_pdf(x: float) -> float {
    return exp(-x*x/2.0) / sqrt(TAU);
}
fn x_times_pdf(x: float) -> float { return x * normal_pdf(x); }
integral_simpson(x_times_pdf, -5.0, 5.0)  // → ~0.0  (symmetric)</pre>

<h2>Sequences &amp; Series</h2>
<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Function</span><span>Description</span></div>
  <div class="gxd-type-row"><code>cumsum(xs)</code><span>Cumulative sum: [x₀, x₀+x₁, x₀+x₁+x₂, …]</span></div>
  <div class="gxd-type-row"><code>cumprod(xs)</code><span>Cumulative product: [x₀, x₀·x₁, …]</span></div>
  <div class="gxd-type-row"><code>sigma(f, from, to)</code><span>Summation Σ f(k) for k = from..to</span></div>
  <div class="gxd-type-row"><code>product(f, from, to)</code><span>Product Π f(k) for k = from..to</span></div>
  <div class="gxd-type-row"><code>taylor_eval(coeffs, x)</code><span>Evaluate polynomial Σ coeffs[k]·xᵏ</span></div>
</div>

<pre class="gxd-code-raw">// Σ k² for k=1..5 = 1+4+9+16+25 = 55
sigma(fn(k) { return float(k*k); }, 1, 5)  // → 55.0

// 5! = 1·2·3·4·5 = 120
product(fn(k) { return float(k); }, 1, 5)  // → 120.0

// Taylor series for e^x around x=0: 1 + x + x²/2! + x³/3! + ...
// coefficients: [1, 1, 0.5, 1/6, 1/24, ...]
let e_coeffs = [1.0, 1.0, 0.5, 0.1666, 0.0416, 0.0083];
taylor_eval(e_coeffs, 1.0)   // → ~2.7182  ≈ e

// Newton's method step: x₁ = x₀ − f(x₀)/f'(x₀)
fn f(x: float) -> float { return x*x - 2.0; }  // find √2
newton_step(f, 1.5)   // → 1.41666... → closer to √2</pre>
`,

/* ─── LINEAR ALGEBRA ────────────────────────────────────── */
math_linalg: `
<h1>Linear Algebra</h1>
<p class="gxd-lead">Linear algebra is the mathematics of vectors and matrices. It underlies machine learning, computer graphics, physics simulations, cryptography, and more. In Gravitix, vectors are <code>list&lt;float&gt;</code> and matrices are <code>list&lt;list&lt;float&gt;&gt;</code>.</p>

<h2>Vectors</h2>
<p>A vector is an ordered list of numbers. It can represent a point in space, a direction, a velocity, or a feature in ML.</p>
<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Function</span><span>Description</span></div>
  <div class="gxd-type-row"><code>dot(a, b)</code><span>Dot product: Σ aᵢ·bᵢ. Result is a scalar. dot(a,b) = |a||b|cos θ</span></div>
  <div class="gxd-type-row"><code>cross(a, b)</code><span>Cross product of two 3D vectors. Result ⊥ both inputs. |a×b| = |a||b|sin θ</span></div>
  <div class="gxd-type-row"><code>norm(v)</code><span>Euclidean length: √(Σ vᵢ²)</span></div>
  <div class="gxd-type-row"><code>normalize(v)</code><span>Unit vector: v / |v|. Length becomes 1.</span></div>
  <div class="gxd-type-row"><code>vec_add(a, b)</code><span>Element-wise addition</span></div>
  <div class="gxd-type-row"><code>vec_sub(a, b)</code><span>Element-wise subtraction</span></div>
  <div class="gxd-type-row"><code>vec_scale(v, s)</code><span>Multiply each element by scalar s</span></div>
</div>

<pre class="gxd-code-raw">let a = [1.0, 2.0, 3.0];
let b = [4.0, 5.0, 6.0];

dot(a, b)        // → 1·4 + 2·5 + 3·6 = 32.0
cross(a, b)      // → [2·6−3·5, 3·4−1·6, 1·5−2·4] = [−3, 6, −3]
norm(a)          // → √(1+4+9) = 3.7416...
normalize(a)     // → [0.267, 0.534, 0.801]  (unit vector)

// Angle between two vectors
fn angle_between(u: list, v: list) -> float {
    return acos(dot(u, v) / (norm(u) * norm(v)));
}
angle_between([1.0,0.0,0.0], [0.0,1.0,0.0])  // → π/2 = 90°</pre>

<h2>Matrices</h2>
<p>A matrix is a 2D array of numbers. An m×n matrix has m rows and n columns. Matrix operations form the core of linear transformations.</p>
<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Function</span><span>Description</span></div>
  <div class="gxd-type-row"><code>mat_add(A, B)</code><span>Element-wise addition of same-size matrices</span></div>
  <div class="gxd-type-row"><code>mat_sub(A, B)</code><span>Element-wise subtraction</span></div>
  <div class="gxd-type-row"><code>mat_mul(A, B)</code><span>Matrix multiplication (A is m×k, B is k×n → result m×n)</span></div>
  <div class="gxd-type-row"><code>mat_scale(A, s)</code><span>Multiply every element by scalar s</span></div>
  <div class="gxd-type-row"><code>transpose(A)</code><span>Swap rows and columns: Aᵀ[i][j] = A[j][i]</span></div>
  <div class="gxd-type-row"><code>det(A)</code><span>Determinant (LU decomposition). Non-zero ↔ invertible.</span></div>
  <div class="gxd-type-row"><code>inv(A)</code><span>Inverse matrix A⁻¹ such that A·A⁻¹ = I (Gauss-Jordan)</span></div>
  <div class="gxd-type-row"><code>trace(A)</code><span>Sum of diagonal elements</span></div>
  <div class="gxd-type-row"><code>rank(A)</code><span>Number of linearly independent rows/columns</span></div>
  <div class="gxd-type-row"><code>identity(n)</code><span>n×n identity matrix (1s on diagonal)</span></div>
  <div class="gxd-type-row"><code>zeros(m, n)</code><span>m×n matrix of zeros</span></div>
  <div class="gxd-type-row"><code>solve(A, b)</code><span>Solve linear system Ax = b via Gaussian elimination</span></div>
  <div class="gxd-type-row"><code>eigenvalues(A)</code><span>Eigenvalues of 2×2 matrix (exact formula)</span></div>
</div>

<pre class="gxd-code-raw">let A = [[1.0, 2.0], [3.0, 4.0]];
let B = [[5.0, 6.0], [7.0, 8.0]];

det(A)            // → 1·4 − 2·3 = −2.0
trace(A)          // → 1 + 4 = 5.0
transpose(A)      // → [[1,3],[2,4]]
mat_mul(A, B)     // → [[1·5+2·7, 1·6+2·8],[3·5+4·7, 3·6+4·8]]
                  //  = [[19,22],[43,50]]

// Solve system: x + 2y = 5, 3x + 4y = 11
let coef = [[1.0, 2.0], [3.0, 4.0]];
let rhs  = [5.0, 11.0];
solve(coef, rhs)  // → [1.0, 2.0]  (x=1, y=2) ✓

// Eigenvalues of [[2,1],[1,2]]: λ = 3 and λ = 1
eigenvalues([[2.0,1.0],[1.0,2.0]])  // → [3.0, 1.0]</pre>
`,

/* ─── NUMBER THEORY ─────────────────────────────────────── */
math_numth: `
<h1>Number Theory</h1>
<p class="gxd-lead">Number theory studies the properties of integers. It is the mathematical foundation of modern cryptography (RSA, elliptic curves, Diffie-Hellman) and has deep connections to physics and pure math.</p>

<h2>Divisibility &amp; GCD</h2>
<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Function</span><span>Description</span></div>
  <div class="gxd-type-row"><code>gcd(a, b)</code><span>Greatest common divisor via Euclidean algorithm. gcd(12,8)=4</span></div>
  <div class="gxd-type-row"><code>lcm(a, b)</code><span>Least common multiple: a·b / gcd(a,b)</span></div>
  <div class="gxd-type-row"><code>divisors(n)</code><span>All positive divisors of n, sorted. divisors(12)=[1,2,3,4,6,12]</span></div>
  <div class="gxd-type-row"><code>euler_phi(n)</code><span>Euler's totient φ(n): count of integers in [1,n] coprime to n</span></div>
  <div class="gxd-type-row"><code>modinv(a, m)</code><span>Modular inverse: x such that a·x ≡ 1 (mod m). Used in RSA.</span></div>
  <div class="gxd-type-row"><code>modpow(base, exp, mod)</code><span>Fast modular exponentiation: base^exp mod. O(log exp).</span></div>
</div>

<pre class="gxd-code-raw">gcd(48, 18)        // → 6
lcm(4, 6)          // → 12
divisors(28)       // → [1, 2, 4, 7, 14, 28]
euler_phi(10)      // → 4  (1,3,7,9 are coprime to 10)

// RSA key generation relies on modinv:
// e·d ≡ 1 (mod φ(n))
modinv(3, 11)      // → 4  because 3·4 = 12 ≡ 1 (mod 11)

// Fast power: 2^100 mod 1000000007
modpow(2, 100, 1000000007)  // → 976371285</pre>

<h2>Primes</h2>
<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Function</span><span>Description</span></div>
  <div class="gxd-type-row"><code>is_prime(n)</code><span>Miller-Rabin primality test (deterministic for n &lt; 3.2×10¹⁸)</span></div>
  <div class="gxd-type-row"><code>primes(n)</code><span>All primes up to n via Sieve of Eratosthenes</span></div>
  <div class="gxd-type-row"><code>prime_factors(n)</code><span>Prime factorization as list. prime_factors(12)=[2,2,3]</span></div>
</div>

<pre class="gxd-code-raw">is_prime(17)          // → true
is_prime(18)          // → false
primes(30)            // → [2,3,5,7,11,13,17,19,23,29]
prime_factors(360)    // → [2,2,2,3,3,5]  (360 = 2³·3²·5)

// Goldbach conjecture checker: every even n>2 is sum of two primes
fn goldbach(n: int) -> str {
    let ps = primes(n);
    for p in ps {
        if is_prime(n - p) {
            return "{n} = {p} + {n-p}";
        }
    }
    return "not found";
}
goldbach(28)   // → "28 = 5 + 23"</pre>

<h2>Combinatorics &amp; Sequences</h2>
<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Function</span><span>Formula</span><span>Description</span></div>
  <div class="gxd-type-row"><code>factorial(n)</code><span>n! = 1·2·…·n</span><span>Permutations of n items</span></div>
  <div class="gxd-type-row"><code>binomial(n, k)</code><span>C(n,k) = n!/(k!·(n−k)!)</span><span>Ways to choose k from n</span></div>
  <div class="gxd-type-row"><code>perm(n, k)</code><span>P(n,k) = n!/(n−k)!</span><span>Ordered selections</span></div>
  <div class="gxd-type-row"><code>fib(n)</code><span>0,1,1,2,3,5,8,13,…</span><span>n-th Fibonacci number</span></div>
  <div class="gxd-type-row"><code>stirling(n, k)</code><span>S(n,k)</span><span>Stirling numbers of second kind: partitions of n into k non-empty subsets</span></div>
  <div class="gxd-type-row"><code>catalan(n)</code><span>C_n = C(2n,n)/(n+1)</span><span>Catalan numbers: bracket sequences, binary trees</span></div>
  <div class="gxd-type-row"><code>harmonic(n)</code><span>Σ 1/k for k=1..n</span><span>Harmonic series partial sum</span></div>
  <div class="gxd-type-row"><code>bernoulli(n)</code><span>B_n</span><span>Bernoulli numbers (appear in Taylor series of trig/log)</span></div>
</div>

<pre class="gxd-code-raw">factorial(10)       // → 3628800
binomial(10, 3)     // → 120  (C(10,3) = 10!/(3!·7!))
perm(10, 3)         // → 720  (10·9·8)
fib(20)             // → 6765
catalan(5)          // → 42   (number of valid bracket sequences of length 10)
harmonic(10)        // → 2.928...  (1 + 1/2 + 1/3 + ... + 1/10)</pre>
`,

/* ─── STATISTICS ────────────────────────────────────────── */
math_stats: `
<h1>Statistics</h1>
<p class="gxd-lead">Statistics provides tools to describe, analyze, and draw conclusions from data. Gravitix includes descriptive statistics, probability distributions, and regression — all from first principles.</p>

<h2>Descriptive statistics</h2>
<p>Given a list of numbers, these functions summarize the data's central tendency and spread:</p>
<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Function</span><span>Description</span></div>
  <div class="gxd-type-row"><code>sum(xs)</code><span>Sum of all elements</span></div>
  <div class="gxd-type-row"><code>avg(xs) / mean(xs)</code><span>Arithmetic mean: Σxᵢ / n</span></div>
  <div class="gxd-type-row"><code>median(xs)</code><span>Middle value when sorted. For even n, average of two middle values.</span></div>
  <div class="gxd-type-row"><code>mode(xs)</code><span>Most frequent value</span></div>
  <div class="gxd-type-row"><code>variance(xs)</code><span>Average squared deviation from mean: Σ(xᵢ−μ)²/n</span></div>
  <div class="gxd-type-row"><code>stddev(xs)</code><span>Standard deviation: √variance. Same units as data.</span></div>
  <div class="gxd-type-row"><code>percentile(xs, p)</code><span>p-th percentile (0≤p≤100). p=50 is median.</span></div>
  <div class="gxd-type-row"><code>zscore(xs)</code><span>Normalize to zero mean unit variance: (xᵢ−μ)/σ</span></div>
  <div class="gxd-type-row"><code>min_of(xs) / max_of(xs)</code><span>Minimum / maximum value</span></div>
</div>

<pre class="gxd-code-raw">let data = [4.0, 7.0, 13.0, 2.0, 1.0, 7.0];

sum(data)           // → 34.0
mean(data)          // → 5.666...
median(data)        // → 5.5  (sorted: [1,2,4,7,7,13], middle avg)
mode(data)          // → 7.0  (appears twice)
variance(data)      // → 14.888...
stddev(data)        // → 3.858...
percentile(data, 75) // → 7.0  (75th percentile)
zscore(data)        // → [−0.432, 0.346, 1.905, −0.950, −1.209, 0.346]

// Exam score analysis
on /stats {
    let scores = [72.0, 85.0, 91.0, 68.0, 95.0, 78.0, 82.0];
    emit "Class average: {mean(scores):.1}";
    emit "Std deviation: {stddev(scores):.1}";
    emit "Top score: {max_of(scores)}";
    emit "Median: {median(scores)}";
}</pre>

<h2>Correlation &amp; Covariance</h2>
<p><strong>Covariance</strong> cov(X,Y) = E[(X−μₓ)(Y−μᵧ)] measures whether two variables move together. <strong>Correlation</strong> r = cov(X,Y)/(σₓ·σᵧ) normalizes this to [−1, 1]:</p>
<ul>
  <li>r = 1: perfect positive relationship (as X grows, Y grows proportionally)</li>
  <li>r = −1: perfect negative relationship</li>
  <li>r ≈ 0: no linear relationship</li>
</ul>
<pre class="gxd-code-raw">let hours_studied = [1.0, 2.0, 3.0, 4.0, 5.0];
let exam_scores   = [50.0, 60.0, 70.0, 80.0, 90.0];

cov(hours_studied, exam_scores)   // → 10.0
corr(hours_studied, exam_scores)  // → 1.0  (perfect linear relation)

let random_data = [1.0, 5.0, 2.0, 8.0, 3.0];
corr(hours_studied, random_data)  // → low, ~0.2  (weak correlation)</pre>

<h2>Probability distributions</h2>
<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Function</span><span>Description</span></div>
  <div class="gxd-type-row"><code>normal_pdf(x, mu?, sigma?)</code><span>PDF of N(μ,σ²): (1/σ√2π)·e^(−(x−μ)²/(2σ²))</span></div>
  <div class="gxd-type-row"><code>normal_cdf(x, mu?, sigma?)</code><span>CDF: P(X ≤ x) for normal distribution. Uses erf approximation.</span></div>
  <div class="gxd-type-row"><code>poisson_pmf(k, lambda)</code><span>P(X=k) = e^(−λ)·λᵏ/k! for Poisson distribution</span></div>
  <div class="gxd-type-row"><code>binomial_pmf(k, n, p)</code><span>P(X=k) = C(n,k)·pᵏ·(1−p)^(n−k)</span></div>
  <div class="gxd-type-row"><code>uniform_rand()</code><span>Uniform random float in [0, 1)</span></div>
  <div class="gxd-type-row"><code>normal_rand(mu?, sigma?)</code><span>Sample from N(μ,σ) using Box-Muller transform</span></div>
</div>

<pre class="gxd-code-raw">// What fraction of people score below 600 on SAT (μ=500, σ=100)?
normal_cdf(600.0, 500.0, 100.0)   // → 0.8413 = 84.1%

// Probability of exactly 3 heads in 10 fair coin flips
binomial_pmf(3, 10, 0.5)          // → 0.1171 = 11.7%

// Average 2 customers/minute, probability of exactly 5 in a minute?
poisson_pmf(5, 2.0)               // → 0.0361 = 3.6%

// Generate random normal data
let sample = [];
let i = 0;
while i < 100 {
    push(sample, normal_rand(0.0, 1.0));
    i += 1;
}
emit "Sample mean (should be ~0): {mean(sample):.3}";</pre>

<h2>Linear regression</h2>
<p><code>linreg(xs, ys)</code> fits the best line y = a + bx through data points using ordinary least squares. Returns <code>[slope, intercept, r_squared]</code>.</p>
<pre class="gxd-code-raw">let x = [1.0, 2.0, 3.0, 4.0, 5.0];
let y = [2.1, 3.9, 6.2, 7.8, 10.1];

let result = linreg(x, y);
let slope     = result[0];   // → ~2.0
let intercept = result[1];   // → ~0.04
let r2        = result[2];   // → ~0.999  (very good fit)

emit "y = {slope:.2}x + {intercept:.2}  (R²={r2:.3})";</pre>
`,

/* ─── SPECIAL FUNCTIONS ─────────────────────────────────── */
math_special: `
<h1>Special Functions</h1>
<p class="gxd-lead">Special functions are solutions to important differential equations or arise naturally in mathematics and physics. They appear in quantum mechanics, thermodynamics, signal processing, and pure analysis.</p>

<h2>Gamma &amp; related functions</h2>
<p>The <strong>Gamma function</strong> Γ(n) is the continuous generalization of factorial: Γ(n) = (n−1)! for positive integers. It extends factorial to real and complex numbers.</p>
<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Function</span><span>Formula / notes</span></div>
  <div class="gxd-type-row"><code>gamma(x)</code><span>Γ(x) = ∫₀^∞ tˣ⁻¹e⁻ᵗdt. Lanczos approximation. Γ(n+1)=n!</span></div>
  <div class="gxd-type-row"><code>lgamma(x)</code><span>ln|Γ(x)|. Avoids overflow for large x.</span></div>
  <div class="gxd-type-row"><code>digamma(x)</code><span>ψ(x) = d/dx ln Γ(x) = Γ'(x)/Γ(x)</span></div>
  <div class="gxd-type-row"><code>beta(a, b)</code><span>B(a,b) = Γ(a)Γ(b)/Γ(a+b) = ∫₀¹ tᵃ⁻¹(1−t)ᵇ⁻¹dt</span></div>
</div>

<pre class="gxd-code-raw">gamma(5.0)    // → 24.0  (= 4! = 24)
gamma(0.5)    // → √π ≈ 1.7724538...
gamma(1.5)    // → √π/2 ≈ 0.8862...

// Beta function: B(2,3) = 1!·2!/4! = 2/24 = 1/12
beta(2.0, 3.0)   // → 0.08333... = 1/12</pre>

<h2>Error function</h2>
<p>The error function erf(x) = (2/√π)∫₀ˣ e^(−t²)dt is the integral of the Gaussian. It is directly related to the normal CDF and appears in heat equations and probability theory.</p>
<pre class="gxd-code-raw">erf(0.0)      // → 0.0
erf(1.0)      // → 0.84270079...
erf(INF)      // → 1.0
erfc(x)       // = 1 − erf(x)  (complementary error function)

// P(−σ &lt; X &lt; σ) for normal distribution
erf(1.0 / sqrt(2.0))   // → 0.6827  = 68.27% (1-sigma rule)</pre>

<h2>Riemann Zeta function</h2>
<p>ζ(s) = Σ 1/nˢ for n=1,2,3,… (when Re(s)>1). Connects to prime distribution via the Euler product. The Riemann Hypothesis (unsolved!) concerns zeros of ζ in the complex plane.</p>
<pre class="gxd-code-raw">zeta(2.0)    // → π²/6 ≈ 1.6449340...  (Basel problem, solved by Euler 1734)
zeta(4.0)    // → π⁴/90 ≈ 1.0823232...
zeta(0.0)    // → −0.5  (analytic continuation)

// Apéry's constant: ζ(3) is irrational but no closed form known
zeta(3.0)    // → 1.20205690315959...</pre>

<h2>Bessel functions</h2>
<p>Bessel functions Jₙ(x) and Yₙ(x) are solutions to Bessel's differential equation: x²y'' + xy' + (x²−n²)y = 0. They appear in wave propagation, heat conduction in cylinders, and quantum mechanics.</p>
<pre class="gxd-code-raw">// J₀(x): oscillates and decays — describes radial waves
bessel_j(0, 2.4048)   // → ~0.0  (first zero of J₀)
bessel_j(1, 0.0)      // → 0.0
bessel_j(0, 0.0)      // → 1.0

// Y₀(x): diverges at x=0, oscillates for large x
bessel_y(0, 1.0)      // → 0.0882...</pre>

<h2>Airy functions</h2>
<p>Ai(x) and Bi(x) are solutions to y'' = xy. They appear in quantum tunneling (WKB approximation) and optics (diffraction).</p>
<pre class="gxd-code-raw">airy_ai(0.0)   // → 0.35502805...
airy_bi(0.0)   // → 0.61492663...

// Ai decays exponentially for x→+∞, oscillates for x→-∞</pre>

<h2>Orthogonal polynomials</h2>
<p>These polynomial families arise as eigenfunctions of important operators and are used in spectral methods, quadrature, and quantum mechanics.</p>
<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Function</span><span>Description &amp; use</span></div>
  <div class="gxd-type-row"><code>legendre(n, x)</code><span>Pₙ(x): orthogonal on [−1,1]. Angular part of hydrogen wavefunctions.</span></div>
  <div class="gxd-type-row"><code>hermite(n, x)</code><span>Hₙ(x): orthogonal w.r.t. e^(−x²). Quantum harmonic oscillator.</span></div>
  <div class="gxd-type-row"><code>chebyshev(n, x)</code><span>Tₙ(x) = cos(n·acos(x)): optimal polynomial approximation.</span></div>
  <div class="gxd-type-row"><code>laguerre(n, x)</code><span>Lₙ(x): orthogonal on [0,∞) w.r.t. e^(−x). Hydrogen radial wavefunctions.</span></div>
</div>

<pre class="gxd-code-raw">legendre(2, 0.5)    // → P₂(x) = (3x²−1)/2 evaluated at x=0.5 → −0.125
hermite(3, 1.0)     // → H₃(x) = 8x³−12x evaluated at x=1 → −4.0
chebyshev(4, 0.5)   // → cos(4·acos(0.5)) = cos(4·π/3) = −0.5

// Orthogonality check: ∫₋₁¹ P₂·P₃ dx = 0
// (different Legendre polynomials are orthogonal)</pre>

<h2>Elliptic integrals</h2>
<p>K(k) and E(k) are complete elliptic integrals of the first and second kind. They compute the period of a nonlinear pendulum and the perimeter of an ellipse.</p>
<pre class="gxd-code-raw">// Period of pendulum with amplitude θ₀:
// T = 4√(L/g) · K(sin(θ₀/2))
fn pendulum_exact(L: float, theta0_deg: float) -> float {
    let k = sin(radians(theta0_deg / 2.0));
    return 4.0 * sqrt(L / 9.81) * elliptic_k(k);
}

// Small angle: T ≈ 2π√(L/g) ≈ 2.006s for L=1m
pendulum_exact(1.0, 10.0)  // → 2.010s  (10° amplitude, slight correction)
pendulum_exact(1.0, 90.0)  // → 2.768s  (90° amplitude, big correction)

// Perimeter of ellipse with semi-axes a, b:
fn ellipse_perimeter(a: float, b: float) -> float {
    let k = sqrt(1.0 - (b/a)**2);
    return 4.0 * a * elliptic_e(k);
}</pre>
`,

/* ─── TRANSFORMS & FFT ──────────────────────────────────── */
math_transforms: `
<h1>Transforms &amp; FFT</h1>
<p class="gxd-lead">The Fourier transform decomposes a signal into its constituent frequencies. It is the mathematical heart of audio processing, telecommunications, image compression (JPEG), and scientific computing. Gravitix provides both DFT and the fast O(n log n) algorithm.</p>

<h2>What the FFT computes</h2>
<p>Given a sequence of N samples x[0], x[1], …, x[N−1], the Discrete Fourier Transform produces N complex frequency components X[k]:</p>
<p style="font-family:monospace;background:var(--bg3);padding:8px 12px;border-radius:6px;">X[k] = Σₙ x[n] · e^(−2πi·k·n/N)</p>
<ul>
  <li>|X[k]| is the <em>amplitude</em> of frequency f = k·sampleRate/N</li>
  <li>arg(X[k]) is the <em>phase</em></li>
  <li>The FFT computes the same result as DFT but in O(n log n) vs O(n²) — for n=1024 that's 1024 operations vs 1 million</li>
</ul>

<div class="gxd-type-table">
  <div class="gxd-type-row gxd-type-header"><span>Function</span><span>Description</span></div>
  <div class="gxd-type-row"><code>fft(xs)</code><span>Fast Fourier Transform (Cooley-Tukey). xs: list of floats or complex. Returns list of complex. Best for N = power of 2.</span></div>
  <div class="gxd-type-row"><code>ifft(Xs)</code><span>Inverse FFT. Reconstructs time-domain signal from spectrum.</span></div>
  <div class="gxd-type-row"><code>dft(xs)</code><span>Naive O(n²) DFT. Same result as fft, works for any N.</span></div>
  <div class="gxd-type-row"><code>convolve(a, b)</code><span>Convolution: (a★b)[n] = Σₖ a[k]·b[n−k]. Used in FIR filters.</span></div>
  <div class="gxd-type-row"><code>laplace_eval(coeffs, s)</code><span>Evaluate Laplace transform polynomial at complex s</span></div>
</div>

<pre class="gxd-code-raw">// Synthesize a signal: sum of 440Hz and 880Hz sine waves
// (sample rate = 8 samples for demo, real use would be 44100)
let N = 8;
let signal = [];
let k = 0;
while k < N {
    let t = float(k) / float(N);
    push(signal, sin(TAU * t) + 0.5 * sin(2.0 * TAU * t));
    k += 1;
}

let spectrum = fft(signal);
// spectrum[1] has amplitude ~1.0  (fundamental frequency)
// spectrum[2] has amplitude ~0.5  (second harmonic)

// Check magnitude of each frequency bin
for i in range(N / 2) {
    let mag = cabs(spectrum[i]);
    if mag > 0.1 {
        emit "Frequency bin {i}: magnitude {mag:.3}";
    }
}

// Convolution: apply box filter (moving average) to smooth data
let data   = [1.0, 3.0, 5.0, 7.0, 5.0, 3.0, 1.0];
let kernel = [0.333, 0.333, 0.333];  // average 3 neighbors
let smooth = convolve(data, kernel);

// Round-trip: fft → ifft should recover original
let recovered = ifft(fft(signal));
// recovered ≈ signal (within floating-point precision)</pre>

<h2>Practical applications</h2>
<pre class="gxd-code-raw">// Find dominant frequency in user-provided data
fn dominant_freq(samples: list, sample_rate: float) -> float {
    let spec = fft(samples);
    let N    = len(samples);
    let max_mag = 0.0;
    let max_k   = 0;
    let k = 1;
    while k < N / 2 {
        let mag = cabs(spec[k]);
        if mag > max_mag {
            max_mag = mag;
            max_k   = k;
        }
        k += 1;
    }
    return float(max_k) * sample_rate / float(N);
}

// Low-pass filter: zero out high-frequency bins
fn lowpass(samples: list, cutoff_bin: int) -> list {
    let spec = fft(samples);
    let N    = len(spec);
    let k = cutoff_bin;
    while k < N - cutoff_bin {
        spec[k] = complex(0.0, 0.0);
        k += 1;
    }
    let result = ifft(spec);
    return result;  // smoothed signal
}</pre>

<div class="gxd-callout gxd-callout-purple">
  <div class="gxd-callout-title">🎵 Why FFT matters</div>
  <p>MP3 and AAC audio compression, JPEG image compression, 5G wireless transmission, radar signal processing, and MRI image reconstruction all rely on the FFT algorithm. Understanding it gives you insight into a huge chunk of modern technology.</p>
</div>
`,
};
