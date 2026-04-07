// ── Starter code ──────────────────────────────────────────────
function STARTER_CODE(name) {
return `// ${name} — Gravitix Bot
// Run with: gravitix run main.grav --token YOUR_TOKEN

state {
    greet_count: int = 0,
}

on /start {
    state.greet_count += 1;
    emit "Hello, {ctx.first_name}! 👋";
    emit "This is visit #{state.greet_count}. Try /help";
}

on /help {
    emit "Commands: /start — greeting  |  /help — this message";
}

on msg {
    match ctx.text {
        /hello|hi/i => emit "Hey there! 👋",
        "ping"      => emit "pong 🏓",
        _           => emit "I didn't understand that. Try /help",
    }
}
`;
}

const TUTORIAL_CODE = `// ══════════════════════════════
//  Gravitix — Quick Tutorial
// ══════════════════════════════

// 1. Variables
let name: str = "Gravitix";
let count: int = 42;

// 2. Functions
fn greet(user: str) -> str {
    return "Hello, {user}!";
}

// 3. Bot state (persists between messages)
state {
    visits: int = 0,
    users: map<int, str> = {},
}

// 4. Command handler
on /start {
    state.visits += 1;
    emit "Hello, {ctx.first_name}!";
}

// 5. Guard (only admins)
on /admin guard ctx.is_admin {
    emit "Welcome, admin!";
}

// 6. Multi-step flow (conversation)
flow register {
    emit "What is your name?";
    let name = wait msg;           // pause until reply
    emit "Nice to meet you, {name}!";
    state.users[ctx.user_id] = name;
}

on /register {
    run flow register;
}

// 7. Pattern matching
on msg {
    match ctx.text {
        /hello|hi/i  => emit "Hey! 👋",
        "ping"       => emit "pong",
        _            => {}
    }
}

// 8. Pipe operator
fn process(s: str) -> str {
    return s |> trim |> lowercase;
}

// 9. Scheduler
every 24 hours {
    emit "Daily reminder!";
}
`;
