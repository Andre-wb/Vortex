// ── Starter code ──────────────────────────────────────────────
function STARTER_CODE(name, lang) {
    if (lang === 'architex') return STARTER_CODE_ARX(name);
    return STARTER_CODE_GRAV(name);
}

function STARTER_CODE_GRAV(name) {
return `// ${name} — Gravitix Bot (Task Manager Backend)
// Handles commands from the Architex Mini App via send()

state {
    tasks:      map<int, list> = {},
    categories: map<int, list> = {},
    next_id:    int = 1,
    stats:      map<str, int>  = {},
}

// ── Helpers ──────────────────────────────────────────────────

fn get_tasks(user_id: int) -> list {
    if state.tasks.has(user_id) {
        return state.tasks[user_id];
    }
    let empty = [];
    state.tasks[user_id] = empty;
    return empty;
}

fn count_by_status(tasks: list, status: str) -> int {
    let n = 0;
    for t in tasks {
        if t.status == status { n += 1; }
    }
    return n;
}

fn count_by_category(tasks: list, cat: str) -> int {
    let n = 0;
    for t in tasks {
        if t.category == cat { n += 1; }
    }
    return n;
}

// ── Bot Commands ─────────────────────────────────────────────

on /start {
    emit "Welcome to {ctx.first_name}'s Task Manager!";
    emit "Use the Mini App for the full UI, or try /stats";
    ui_set("user_name", ctx.first_name);
    ui_set("initialized", true);
}

on /help {
    emit """Commands:
/start  — initialize bot
/stats  — your task statistics
/clear  — remove completed tasks
/export — export tasks as text""";
}

on /stats {
    let tasks = get_tasks(ctx.user_id);
    let total = len(tasks);
    let done  = count_by_status(tasks, "done");
    let active = total - done;
    emit "📊 Stats for {ctx.first_name}:";
    emit "  Active: {active}  |  Done: {done}  |  Total: {total}";
}

on /clear {
    let tasks = get_tasks(ctx.user_id);
    let kept = [];
    let removed = 0;
    for t in tasks {
        if t.status != "done" {
            push(kept, t);
        } else {
            removed += 1;
        }
    }
    state.tasks[ctx.user_id] = kept;
    emit "Cleared {removed} completed task(s). {len(kept)} remaining.";
    ui_set("tasks", kept);
    ui_set("task_count", len(kept));
}

// ── Mini App Bridge (handles send() from Architex) ──────────

on msg {
    match ctx.text {
        /hello|hi/i => emit "Hey! Open the Mini App for the full task manager.",
        "ping"      => emit "pong",
        _           => {}
    }
}

on callback "add_task" {
    let tasks = get_tasks(ctx.user_id);
    let task = {
        id: state.next_id,
        title: ctx.callback_data.title,
        category: ctx.callback_data.category,
        priority: ctx.callback_data.priority,
        status: "active",
        created: now_unix(),
    };
    state.next_id += 1;
    push(tasks, task);
    state.tasks[ctx.user_id] = tasks;

    ui_set("tasks", tasks);
    ui_set("task_count", len(tasks));
    ui_set("last_action", "Task added: {task.title}");
    emit "Added: {task.title} [{task.category}]";
}

on callback "toggle_task" {
    let tasks = get_tasks(ctx.user_id);
    let task_id = ctx.callback_data.id;
    for t in tasks {
        if t.id == task_id {
            if t.status == "active" {
                t.status = "done";
            } else {
                t.status = "active";
            }
        }
    }
    state.tasks[ctx.user_id] = tasks;

    let done = count_by_status(tasks, "done");
    let total = len(tasks);
    let progress = 0;
    if total > 0 { progress = (done * 100) / total; }

    ui_set("tasks", tasks);
    ui_set("done_count", done);
    ui_set("progress", progress);
}

on callback "delete_task" {
    let tasks = get_tasks(ctx.user_id);
    let task_id = ctx.callback_data.id;
    let updated = [];
    for t in tasks {
        if t.id != task_id {
            push(updated, t);
        }
    }
    state.tasks[ctx.user_id] = updated;
    ui_set("tasks", updated);
    ui_set("task_count", len(updated));
    emit "Task deleted.";
}

on callback "get_stats" {
    let tasks = get_tasks(ctx.user_id);
    let total  = len(tasks);
    let done   = count_by_status(tasks, "done");
    let active = total - done;

    let work_count     = count_by_category(tasks, "Work");
    let personal_count = count_by_category(tasks, "Personal");
    let urgent_count   = count_by_category(tasks, "Urgent");
    let ideas_count    = count_by_category(tasks, "Ideas");

    ui_set("stat_total", total);
    ui_set("stat_done", done);
    ui_set("stat_active", active);
    ui_set("stat_work", work_count);
    ui_set("stat_personal", personal_count);
    ui_set("stat_urgent", urgent_count);
    ui_set("stat_ideas", ideas_count);
    ui_set("progress", if total > 0 { (done * 100) / total } else { 0 });
}

on callback "search_tasks" {
    let tasks = get_tasks(ctx.user_id);
    let query = ctx.callback_data.query |> trim |> lowercase;
    let results = [];
    for t in tasks {
        if contains(lowercase(t.title), query) {
            push(results, t);
        }
    }
    ui_set("search_results", results);
    ui_set("search_count", len(results));
}

// ── Daily reminder ───────────────────────────────────────────

every 24 hours {
    for user_id in state.tasks.keys() {
        let tasks = state.tasks[user_id];
        let active = count_by_status(tasks, "active");
        if active > 0 {
            emit_to(user_id, "You have {active} active task(s). Stay productive!");
        }
    }
}
`;
}

function STARTER_CODE_ARX(name) {
return `// ${name} — Task Manager Mini App
// A full-featured task manager with categories, search, and stats

@theme
  primary   = #6C5CE7
  secondary = #A29BFE
  accent    = #FD79A8
  success   = #00B894
  warning   = #FDCB6E
  danger    = #E17055
  surface   = #F8F9FE
  text      = #2D3436
  muted     = #B2BEC3

// ══════════════════════════════════════════
//  Reusable Components
// ══════════════════════════════════════════

@component TaskCard
  card :: pad(16) radius(12) bg(#fff) border(#E8E8F0)
    row :: gap(12) center
      button ~task_icon :: pad(8) radius(20) bg(~task_color)
        => send(action: "toggle_task", id: ~task_id)
      col :: gap(4) grow
        text ~task_title :: bold size(15) color(#2D3436)
        row :: gap(8)
          badge ~task_category :: size(11) radius(8) bg(#F0EFFF) color(#6C5CE7)
          badge ~task_priority :: size(11) radius(8) bg(~priority_bg) color(~priority_color)
      button "×" :: pad(8) radius(8) bg(#FFF0F0) color(#E17055) size(16)
        => send(action: "delete_task", id: ~task_id)

@component StatCard
  card :: pad(16) radius(12) bg(~stat_bg) border(~stat_border)
    col :: gap(6) center
      text ~stat_value :: bold size(28) color(~stat_accent)
      text ~stat_label :: size(12) color(#636E72)

@component CategoryChip
  button ~chip_label :: pad(10) radius(20) bg(~chip_bg) color(~chip_color) size(13)
    => ~selected_category = ~chip_value

// ══════════════════════════════════════════
//  Main Screen — Task List
// ══════════════════════════════════════════

@screen Main

  ~app_title = "${name}"
  ~user_name = "User"
  ~search_query = ""
  ~selected_category = "All"
  ~new_task_title = ""
  ~new_task_category = "Work"
  ~new_task_priority = "Medium"
  ~show_add_form = false
  ~task_count = 0
  ~done_count = 0
  ~progress = 0
  ~filter_active = true

  col :: pad(0) gap(0) bg(#F8F9FE)

    // ── Top Bar ──────────────────────────
    col :: pad(20) gap(12) bg(#6C5CE7)
      row :: gap(12) center
        col :: grow
          text ~app_title :: bold size(22) color(#fff)
          text "Stay organized, stay productive" :: size(13) color(#D5D0F7)
        button "Stats" :: pad(10) radius(10) bg(#5A4BD1) color(#fff) size(13)
          => navigate(Stats)

      // ── Search Bar ───────────────────
      row :: gap(8)
        input ~search_query :: pad(12) radius(10) bg(#5A4BD1) color(#fff) placeholder("Search tasks...") grow
          => send(action: "search_tasks", query: ~search_query)
        button "+" :: pad(12) radius(10) bg(#FD79A8) color(#fff) bold size(18)
          => ~show_add_form = !~show_add_form

    // ── Quick Stats Row ──────────────────
    row :: pad(16) gap(12) center
      col :: gap(2) center grow
        text ~task_count :: bold size(20) color(#6C5CE7)
        text "Total" :: size(11) color(#B2BEC3)
      col :: gap(2) center grow
        text ~done_count :: bold size(20) color(#00B894)
        text "Done" :: size(11) color(#B2BEC3)
      col :: gap(2) center grow
        text ~progress :: bold size(20) color(#FD79A8)
        text "% Complete" :: size(11) color(#B2BEC3)

    divider

    // ── Add Task Form (collapsible) ──────
    @if ~show_add_form
      card :: pad(16) radius(12) bg(#fff) border(#E8E8F0)
        col :: gap(12)
          text "New Task" :: bold size(16) color(#2D3436)
          input ~new_task_title :: pad(12) radius(8) border(#DDD) placeholder("What needs to be done?")
            => ~new_task_title = ~new_task_title
          row :: gap(8)
            text "Category:" :: size(13) color(#636E72)
            button "Work" :: pad(8) radius(8) bg(#F0EFFF) color(#6C5CE7) size(12)
              => ~new_task_category = "Work"
            button "Personal" :: pad(8) radius(8) bg(#E8F8F5) color(#00B894) size(12)
              => ~new_task_category = "Personal"
            button "Urgent" :: pad(8) radius(8) bg(#FFEEF0) color(#E17055) size(12)
              => ~new_task_category = "Urgent"
            button "Ideas" :: pad(8) radius(8) bg(#FFF8E1) color(#F39C12) size(12)
              => ~new_task_category = "Ideas"
          row :: gap(8)
            text "Priority:" :: size(13) color(#636E72)
            button "Low" :: pad(8) radius(8) bg(#E8F8F5) color(#00B894) size(12)
              => ~new_task_priority = "Low"
            button "Medium" :: pad(8) radius(8) bg(#FFF8E1) color(#F39C12) size(12)
              => ~new_task_priority = "Medium"
            button "High" :: pad(8) radius(8) bg(#FFEEF0) color(#E17055) size(12)
              => ~new_task_priority = "High"
          row :: gap(8)
            badge ~new_task_category :: size(12) radius(8) bg(#F0EFFF) color(#6C5CE7)
            badge ~new_task_priority :: size(12) radius(8) bg(#FFF8E1) color(#F39C12)
          button "Add Task" :: pad(14) radius(10) bg(#6C5CE7) color(#fff) bold size(14) center
            => send(action: "add_task", title: ~new_task_title, category: ~new_task_category, priority: ~new_task_priority)

    // ── Category Filter ──────────────────
    row :: pad(16) gap(8)
      button "All" :: pad(8) radius(20) bg(#6C5CE7) color(#fff) size(13)
        => ~selected_category = "All"
      button "Work" :: pad(8) radius(20) bg(#F0EFFF) color(#6C5CE7) size(13)
        => ~selected_category = "Work"
      button "Personal" :: pad(8) radius(20) bg(#E8F8F5) color(#00B894) size(13)
        => ~selected_category = "Personal"
      button "Urgent" :: pad(8) radius(20) bg(#FFEEF0) color(#E17055) size(13)
        => ~selected_category = "Urgent"
      button "Ideas" :: pad(8) radius(20) bg(#FFF8E1) color(#F39C12) size(13)
        => ~selected_category = "Ideas"

    // ── Task List ────────────────────────
    col :: pad(16) gap(10)

      // Sample tasks to preview the UI
      card :: pad(16) radius(12) bg(#fff) border(#E8E8F0)
        row :: gap(12) center
          button "○" :: pad(8) radius(20) bg(#F0EFFF) color(#6C5CE7)
            => send(action: "toggle_task", id: 1)
          col :: gap(4) grow
            text "Design new landing page" :: bold size(15) color(#2D3436)
            row :: gap(8)
              badge "Work" :: size(11) radius(8) bg(#F0EFFF) color(#6C5CE7)
              badge "High" :: size(11) radius(8) bg(#FFEEF0) color(#E17055)
          button "×" :: pad(8) radius(8) bg(#FFF0F0) color(#E17055) size(16)
            => send(action: "delete_task", id: 1)

      card :: pad(16) radius(12) bg(#fff) border(#E8E8F0)
        row :: gap(12) center
          button "●" :: pad(8) radius(20) bg(#00B894) color(#fff)
            => send(action: "toggle_task", id: 2)
          col :: gap(4) grow
            text "Buy groceries" :: bold size(15) color(#B2BEC3)
            row :: gap(8)
              badge "Personal" :: size(11) radius(8) bg(#E8F8F5) color(#00B894)
              badge "Low" :: size(11) radius(8) bg(#E8F8F5) color(#00B894)
          button "×" :: pad(8) radius(8) bg(#FFF0F0) color(#E17055) size(16)
            => send(action: "delete_task", id: 2)

      card :: pad(16) radius(12) bg(#fff) border(#E8E8F0)
        row :: gap(12) center
          button "○" :: pad(8) radius(20) bg(#F0EFFF) color(#6C5CE7)
            => send(action: "toggle_task", id: 3)
          col :: gap(4) grow
            text "Fix authentication bug" :: bold size(15) color(#2D3436)
            row :: gap(8)
              badge "Urgent" :: size(11) radius(8) bg(#FFEEF0) color(#E17055)
              badge "High" :: size(11) radius(8) bg(#FFEEF0) color(#E17055)
          button "×" :: pad(8) radius(8) bg(#FFF0F0) color(#E17055) size(16)
            => send(action: "delete_task", id: 3)

      card :: pad(16) radius(12) bg(#fff) border(#E8E8F0)
        row :: gap(12) center
          button "○" :: pad(8) radius(20) bg(#F0EFFF) color(#6C5CE7)
            => send(action: "toggle_task", id: 4)
          col :: gap(4) grow
            text "Brainstorm app features" :: bold size(15) color(#2D3436)
            row :: gap(8)
              badge "Ideas" :: size(11) radius(8) bg(#FFF8E1) color(#F39C12)
              badge "Medium" :: size(11) radius(8) bg(#FFF8E1) color(#F39C12)
          button "×" :: pad(8) radius(8) bg(#FFF0F0) color(#E17055) size(16)
            => send(action: "delete_task", id: 4)

    // ── Bottom Navigation ────────────────
    divider
    row :: pad(12) gap(0) center bg(#fff)
      button "Tasks" :: pad(12) grow center color(#6C5CE7) bold size(13)
        => navigate(Main)
      button "Stats" :: pad(12) grow center color(#B2BEC3) size(13)
        => navigate(Stats)
      button "Settings" :: pad(12) grow center color(#B2BEC3) size(13)
        => navigate(Settings)

// ══════════════════════════════════════════
//  Stats Screen — Analytics Dashboard
// ══════════════════════════════════════════

@screen Stats

  ~stat_total = 0
  ~stat_done = 0
  ~stat_active = 0
  ~stat_work = 0
  ~stat_personal = 0
  ~stat_urgent = 0
  ~stat_ideas = 0
  ~progress = 0

  @onMount
    send(action: "get_stats")

  col :: pad(0) gap(0) bg(#F8F9FE)

    // ── Header ───────────────────────────
    col :: pad(20) gap(8) bg(#6C5CE7)
      row :: gap(12) center
        button "←" :: pad(8) radius(8) bg(#5A4BD1) color(#fff) size(16)
          => back()
        text "Statistics" :: bold size(22) color(#fff) grow
      text "Your productivity at a glance" :: size(13) color(#D5D0F7)

    // ── Progress Overview ────────────────
    col :: pad(20) gap(16)

      card :: pad(20) radius(16) bg(#fff) border(#E8E8F0)
        col :: gap(12) center
          text "Overall Progress" :: bold size(16) color(#2D3436)
          text ~progress :: bold size(48) color(#6C5CE7)
          text "percent complete" :: size(13) color(#B2BEC3)

      // ── Stat Cards Grid ────────────────
      row :: gap(12)
        card :: pad(16) radius(12) bg(#F0EFFF) border(#E0DEFF) grow
          col :: gap(6) center
            text ~stat_total :: bold size(28) color(#6C5CE7)
            text "Total" :: size(12) color(#636E72)
        card :: pad(16) radius(12) bg(#E8F8F5) border(#C8F0E8) grow
          col :: gap(6) center
            text ~stat_done :: bold size(28) color(#00B894)
            text "Completed" :: size(12) color(#636E72)
      row :: gap(12)
        card :: pad(16) radius(12) bg(#FFF0F5) border(#FFE0EA) grow
          col :: gap(6) center
            text ~stat_active :: bold size(28) color(#FD79A8)
            text "Active" :: size(12) color(#636E72)
        card :: pad(16) radius(12) bg(#FFF8E1) border(#FFE8A1) grow
          col :: gap(6) center
            text "0" :: bold size(28) color(#F39C12)
            text "Overdue" :: size(12) color(#636E72)

      // ── By Category ────────────────────
      card :: pad(20) radius(12) bg(#fff) border(#E8E8F0)
        col :: gap(14)
          text "By Category" :: bold size(16) color(#2D3436)
          row :: gap(12) center
            badge "Work" :: size(12) radius(8) bg(#F0EFFF) color(#6C5CE7)
            text ~stat_work :: bold size(16) color(#2D3436) grow
          row :: gap(12) center
            badge "Personal" :: size(12) radius(8) bg(#E8F8F5) color(#00B894)
            text ~stat_personal :: bold size(16) color(#2D3436) grow
          row :: gap(12) center
            badge "Urgent" :: size(12) radius(8) bg(#FFEEF0) color(#E17055)
            text ~stat_urgent :: bold size(16) color(#2D3436) grow
          row :: gap(12) center
            badge "Ideas" :: size(12) radius(8) bg(#FFF8E1) color(#F39C12)
            text ~stat_ideas :: bold size(16) color(#2D3436) grow

      button "Refresh Stats" :: pad(14) radius(10) bg(#6C5CE7) color(#fff) bold size(14) center
        => send(action: "get_stats")

    // ── Bottom Navigation ────────────────
    divider
    row :: pad(12) gap(0) center bg(#fff)
      button "Tasks" :: pad(12) grow center color(#B2BEC3) size(13)
        => navigate(Main)
      button "Stats" :: pad(12) grow center color(#6C5CE7) bold size(13)
        => navigate(Stats)
      button "Settings" :: pad(12) grow center color(#B2BEC3) size(13)
        => navigate(Settings)

// ══════════════════════════════════════════
//  Settings Screen
// ══════════════════════════════════════════

@screen Settings

  ~user_name = "User"
  ~notifications = true
  ~dark_mode = false
  ~daily_reminder = true

  col :: pad(0) gap(0) bg(#F8F9FE)

    // ── Header ───────────────────────────
    col :: pad(20) gap(8) bg(#6C5CE7)
      row :: gap(12) center
        button "←" :: pad(8) radius(8) bg(#5A4BD1) color(#fff) size(16)
          => back()
        text "Settings" :: bold size(22) color(#fff) grow

    col :: pad(20) gap(12)

      // ── Profile Section ────────────────
      card :: pad(20) radius(12) bg(#fff) border(#E8E8F0)
        col :: gap(16)
          text "Profile" :: bold size(16) color(#2D3436)
          row :: gap(12) center
            badge "U" :: pad(16) radius(24) bg(#6C5CE7) color(#fff) bold size(20)
            col :: gap(4) grow
              text ~user_name :: bold size(16) color(#2D3436)
              text "Manage your account" :: size(13) color(#B2BEC3)

      // ── Preferences ────────────────────
      card :: pad(20) radius(12) bg(#fff) border(#E8E8F0)
        col :: gap(16)
          text "Preferences" :: bold size(16) color(#2D3436)

          row :: gap(12) center
            col :: grow
              text "Push Notifications" :: size(14) color(#2D3436)
              text "Get notified about task deadlines" :: size(12) color(#B2BEC3)
            button "On" :: pad(8) radius(8) bg(#E8F8F5) color(#00B894) size(12)
              => ~notifications = !~notifications

          divider

          row :: gap(12) center
            col :: grow
              text "Daily Reminder" :: size(14) color(#2D3436)
              text "Morning summary of active tasks" :: size(12) color(#B2BEC3)
            button "On" :: pad(8) radius(8) bg(#E8F8F5) color(#00B894) size(12)
              => ~daily_reminder = !~daily_reminder

          divider

          row :: gap(12) center
            col :: grow
              text "Dark Mode" :: size(14) color(#2D3436)
              text "Switch to dark theme" :: size(12) color(#B2BEC3)
            button "Off" :: pad(8) radius(8) bg(#F0F0F0) color(#B2BEC3) size(12)
              => ~dark_mode = !~dark_mode

      // ── Data Management ────────────────
      card :: pad(20) radius(12) bg(#fff) border(#E8E8F0)
        col :: gap(12)
          text "Data" :: bold size(16) color(#2D3436)
          button "Export Tasks" :: pad(14) radius(10) bg(#F0EFFF) color(#6C5CE7) size(14) center
            => send(action: "export_tasks")
          button "Clear Completed" :: pad(14) radius(10) bg(#FFF0F0) color(#E17055) size(14) center
            => send(action: "clear_done")

      // ── About ──────────────────────────
      card :: pad(20) radius(12) bg(#fff) border(#E8E8F0)
        col :: gap(8) center
          text "${name}" :: bold size(14) color(#2D3436)
          text "Built with Architex + Gravitix" :: size(12) color(#B2BEC3)
          text "Vortex Platform" :: size(12) color(#6C5CE7)

    // ── Bottom Navigation ────────────────
    divider
    row :: pad(12) gap(0) center bg(#fff)
      button "Tasks" :: pad(12) grow center color(#B2BEC3) size(13)
        => navigate(Main)
      button "Stats" :: pad(12) grow center color(#B2BEC3) size(13)
        => navigate(Stats)
      button "Settings" :: pad(12) grow center color(#6C5CE7) bold size(13)
        => navigate(Settings)
`;
}

const TUTORIAL_CODE_ARX = `// ══════════════════════════════
//  Architex — Quick Tutorial
// ══════════════════════════════

// 1. Screen — top-level view
@screen Main

  // 2. Reactive state (~ prefix)
  ~name = "World"
  ~count = 0

  // 3. Computed value (:= auto-updates)
  ~greeting := "Hello, {~name}!"

  // 4. Layout with modifiers (:: syntax)
  col :: pad(24) gap(16)

    header ~greeting :: bold size(22) color(#4f8ef7)

    // 5. Input bound to reactive var
    input ~name :: pad(10) radius(8) border(#ccc) placeholder("Your name")
      => ~name = ~name

    // 6. Buttons with handlers (=> syntax)
    row :: gap(12) center
      button "−" :: pad(12) radius(8) bg(#f0f0f0)
        => ~count -= 1
      button "+" :: pad(12) radius(8) bg(#e0f0e0)
        => ~count += 1

    text ~count :: size(36) bold center

    divider

    // 7. Conditional rendering
    @if ~count > 5
      text "High count!" :: bold color(#e53935)
    @else
      text "Keep clicking..." :: italic color(#999)

    // 8. Send data to Gravitix bot
    button "Send to Bot" :: pad(12) radius(12) bg(#4f8ef7) color(#fff)
      => send(action: "from_ui", name: ~name, count: ~count)

    // 9. Navigation
    button "Go to About →" :: pad(10) radius(8) bg(#eee)
      => navigate(About)

@screen About
  col :: pad(24) gap(16)
    header "About" :: bold size(22)
    text "Architex is a declarative UI language for Vortex Mini Apps."
    button "← Back" :: pad(10) radius(8) bg(#eee)
      => back()
`;

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
