// ── Starter code ──────────────────────────────────────────────
function STARTER_CODE(name, lang) {
    if (lang === 'architex') return STARTER_CODE_ARX(name);
    return STARTER_CODE_GRAV(name);
}

function STARTER_CODE_GRAV(name) {
return `// ${name} — Gravitix Math Engine
// Backend for the Architex Calculator Mini App

state {
    history: list = [],
    history_id: int = 0,
}

// ── Derivative Engine ───────────────────────────────────────

fn derivative(expr: str) -> str {
    // Power rule: ax^n → n*a*x^(n-1)
    let e = expr |> trim;
    match e {
        /^(-?\\d*\\.?\\d*)x\\^(\\d+)$/ => {
            let coef = if ctx.match[1] == "" or ctx.match[1] == "-" {
                if ctx.match[1] == "-" { -1 } else { 1 }
            } else { float(ctx.match[1]) };
            let exp = int(ctx.match[2]);
            let nc = coef * exp;
            let ne = exp - 1;
            if ne == 0 { return str(nc) }
            if ne == 1 { return "{nc}x" }
            return "{nc}x^{ne}";
        },
        /^(-?\\d*\\.?\\d*)x$/ => {
            let c = if ctx.match[1] == "" { "1" } else { ctx.match[1] };
            return c;
        },
        /^(-?\\d+\\.?\\d*)$/ => return "0",
        "sin(x)"  => return "cos(x)",
        "cos(x)"  => return "-sin(x)",
        "tan(x)"  => return "1/cos^2(x)",
        "e^x"     => return "e^x",
        "ln(x)"   => return "1/x",
        "sqrt(x)" => return "1/(2*sqrt(x))",
        _          => return "d/dx[{e}]"
    }
}

fn integral(expr: str) -> str {
    let e = expr |> trim;
    match e {
        /^(-?\\d*\\.?\\d*)x\\^(\\d+)$/ => {
            let coef = if ctx.match[1] == "" { 1.0 } else { float(ctx.match[1]) };
            let exp = int(ctx.match[2]);
            let ne = exp + 1;
            let nc = coef / ne;
            return "{nc}x^{ne} + C";
        },
        /^(-?\\d*\\.?\\d*)x$/ => {
            let c = if ctx.match[1] == "" { 1.0 } else { float(ctx.match[1]) };
            let nc = c / 2.0;
            return "{nc}x^2 + C";
        },
        /^(-?\\d+\\.?\\d*)$/ => return "{e}x + C",
        "sin(x)"  => return "-cos(x) + C",
        "cos(x)"  => return "sin(x) + C",
        "e^x"     => return "e^x + C",
        "1/x"     => return "ln|x| + C",
        _          => return "\\u222B {e} dx"
    }
}

fn solve_quadratic(a: float, b: float, c: float) -> str {
    let D = b * b - 4.0 * a * c;
    if D < 0 {
        let re = -b / (2.0 * a);
        let im = sqrt(-D) / (2.0 * a);
        return "x = {re} \\u00B1 {im}i  (D={D})";
    }
    if D == 0 {
        let x = -b / (2.0 * a);
        return "x = {x}  (D=0, one root)";
    }
    let x1 = (-b + sqrt(D)) / (2.0 * a);
    let x2 = (-b - sqrt(D)) / (2.0 * a);
    return "x\\u2081 = {x1},  x\\u2082 = {x2}  (D={D})";
}

fn calc_limit(expr: str, point: str) -> str {
    match expr {
        "sin(x)/x"     => return "1",
        "(1+1/x)^x"    => return "e \\u2248 2.71828",
        "(e^x-1)/x"    => return "1",
        "x/|x|"        => return "DNE (\\u00B11)",
        "1/x"          => {
            if point == "0" { return "\\u00B1\\u221E" }
            return str(1.0 / float(point));
        },
        "ln(x)/x"      => return "0",
        _               => return "lim({expr})"
    }
}

fn matrix_det(a: float, b: float, c: float, d: float) -> float {
    return a * d - b * c;
}

fn matrix_trace(a: float, d: float) -> float {
    return a + d;
}

// ── Bot Commands ─────────────────────────────────────────────

on /start {
    emit "\\u{1F9EE} {ctx.first_name}, welcome to Math Calculator!";
    emit "Open the Mini App for the full calculator UI.";
    emit "Or type: /deriv x^3, /integ sin(x), /solve 1 -5 6";
}

on /deriv {
    let expr = join(ctx.args, " ");
    let result = derivative(expr);
    emit "d/dx [{expr}] = {result}";
}

on /integ {
    let expr = join(ctx.args, " ");
    let result = integral(expr);
    emit "\\u222B {expr} dx = {result}";
}

on /solve {
    if len(ctx.args) < 3 { emit "Usage: /solve a b c"; stop }
    let a = float(ctx.args[0]);
    let b = float(ctx.args[1]);
    let c = float(ctx.args[2]);
    emit solve_quadratic(a, b, c);
}

// ── Mini App Bridge ─────────────────────────────────────────

on msg {
    match ctx.action {
        "derivative" => {
            let r = derivative(ctx.expr);
            ui_set("deriv_result", r);
            state.history_id += 1;
            push(state.history, {id: state.history_id, op: "d/dx", expr: ctx.expr, result: r});
            ui_set("history_count", len(state.history));
        },
        "integral" => {
            let r = integral(ctx.expr);
            ui_set("integ_result", r);
            state.history_id += 1;
            push(state.history, {id: state.history_id, op: "\\u222B", expr: ctx.expr, result: r});
            ui_set("history_count", len(state.history));
        },
        "quadratic" => {
            let r = solve_quadratic(float(ctx.a), float(ctx.b), float(ctx.c));
            ui_set("quad_result", r);
            state.history_id += 1;
            push(state.history, {id: state.history_id, op: "ax\\u00B2+bx+c", expr: "{ctx.a}x\\u00B2+{ctx.b}x+{ctx.c}", result: r});
        },
        "limit" => {
            let r = calc_limit(ctx.expr, ctx.point);
            ui_set("limit_result", r);
            state.history_id += 1;
            push(state.history, {id: state.history_id, op: "lim", expr: ctx.expr, result: r});
        },
        "determinant" => {
            let det = matrix_det(float(ctx.a), float(ctx.b), float(ctx.c), float(ctx.d));
            let tr = matrix_trace(float(ctx.a), float(ctx.d));
            ui_set("mat_det", str(det));
            ui_set("mat_trace", str(tr));
        },
        "clear_history" => {
            state.history = [];
            ui_set("history_count", 0);
        },
        _ => {}
    }
}
`;
}

function STARTER_CODE_ARX(name) {
return `// ${name} — Advanced Math Calculator
// Derivatives, Integrals, Equations, Matrices, Limits

@theme
  primary   = #0F0A2E
  secondary = #1A1145
  accent    = #7B5EFF
  neon      = #00F0FF
  gold      = #FFD700
  success   = #00E676
  danger    = #FF4081
  surface   = #16103A
  text      = #E8E0FF
  muted     = #7B73A0

// ══════════════════════════════════════════
//  Main — Calculator Dashboard
// ══════════════════════════════════════════

@screen Main

  ~history_count = 0

  col :: pad(0) gap(0) bg(#0F0A2E)

    // ── Header with gradient ────────────
    col :: pad(24) gap(8) gradient(#1A1145-#2A1060-#1A1145)
      text "${name}" :: bold size(24) color(#fff) animate(fadeIn)
      text "Advanced Mathematics Calculator" :: size(13) color(#7B73A0)

    col :: pad(20) gap(14)

      // ── Category Cards with SVG icons ──
      row :: gap(12)
        card :: pad(18) radius(14) bg(#1E1650) border(#2A2060) grow glow(#7B5EFF) animate(fadeIn)
          col :: gap(10) center
            mathicon "derivative" :: size(40) color(#7B5EFF) animate(float)
            text "Derivatives" :: bold size(13) color(#C4B5FD)
            button "Open" :: pad(8) radius(8) gradient(#7B5EFF-#6C4FEE) color(#fff) size(12)
              => navigate(Derivative)
        card :: pad(18) radius(14) bg(#1E1650) border(#2A2060) grow glow(#00F0FF) animate(fadeIn)
          col :: gap(10) center
            mathicon "integral" :: size(40) color(#00F0FF) animate(float)
            text "Integrals" :: bold size(13) color(#67E8F9)
            button "Open" :: pad(8) radius(8) gradient(#00B8D4-#00897B) color(#fff) size(12)
              => navigate(Integral)

      row :: gap(12)
        card :: pad(18) radius(14) bg(#1E1650) border(#2A2060) grow glow(#FFD700) animate(fadeIn)
          col :: gap(10) center
            mathicon "equation" :: size(40) color(#FFD700) animate(float)
            text "Equations" :: bold size(13) color(#FDE68A)
            button "Open" :: pad(8) radius(8) gradient(#FFD700-#F59E0B) color(#0F0A2E) size(12)
              => navigate(Equations)
        card :: pad(18) radius(14) bg(#1E1650) border(#2A2060) grow glow(#00E676) animate(fadeIn)
          col :: gap(10) center
            mathicon "matrix" :: size(40) color(#00E676) animate(float)
            text "Matrices" :: bold size(13) color(#6EE7B7)
            button "Open" :: pad(8) radius(8) gradient(#00E676-#059669) color(#fff) size(12)
              => navigate(Matrix)

      row :: gap(12)
        card :: pad(18) radius(14) bg(#1E1650) border(#2A2060) grow glow(#FF4081) animate(fadeIn)
          col :: gap(10) center
            mathicon "limit" :: size(40) color(#FF4081) animate(float)
            text "Limits" :: bold size(13) color(#FDA4AF)
            button "Open" :: pad(8) radius(8) gradient(#FF4081-#E91E63) color(#fff) size(12)
              => navigate(Limits)
        card :: pad(18) radius(14) bg(#1E1650) border(#2A2060) grow glow(#FF9100) animate(fadeIn)
          col :: gap(10) center
            mathicon "sigma" :: size(40) color(#FF9100) animate(float)
            text "Reference" :: bold size(13) color(#FDBA74)
            button "Open" :: pad(8) radius(8) gradient(#FF9100-#E65100) color(#fff) size(12)
              => navigate(Reference)

      // ── Quick Formulas with glow ──────
      card :: pad(18) radius(14) bg(#1E1650) border(#2A2060) glass
        col :: gap(10)
          text "Quick Formulas" :: bold size(15) color(#fff)
          row :: gap(8)
            badge "(a+b)\\u00B2 = a\\u00B2+2ab+b\\u00B2" :: size(11) radius(8) bg(#2A1F6E) color(#7B5EFF)
          row :: gap(8)
            badge "sin\\u00B2+cos\\u00B2 = 1" :: size(11) radius(8) bg(#0A2A30) color(#00F0FF)
          row :: gap(8)
            badge "e^(i\\u03C0) + 1 = 0" :: size(11) radius(8) bg(#2A0A20) color(#FF4081)

      // ── History count ─────────────────
      card :: pad(14) radius(12) bg(#16103A) border(#2A2060) glass
        row :: gap(12) center
          text "History" :: size(14) color(#7B73A0)
          text ~history_count :: bold size(14) color(#7B5EFF) animate(pulse)
          text "calculations" :: size(14) color(#7B73A0) grow
          button "Clear" :: pad(6) radius(6) bg(#2A0A20) color(#FF4081) size(11)
            => send(action: "clear_history")

// ══════════════════════════════════════════
//  Derivative Calculator
// ══════════════════════════════════════════

@screen Derivative

  ~deriv_input = ""
  ~deriv_result = ""

  col :: pad(0) gap(0) bg(#0F0A2E)

    // ── Header ──────────────────────────
    col :: pad(20) gap(6) gradient(#1A1145-#1E1650)
      row :: gap(12) center
        button "\\u2190" :: pad(8) radius(8) bg(#2A1F6E) color(#7B5EFF) size(16)
          => back()
        mathicon "derivative" :: size(28) color(#7B5EFF) animate(glow)
        col :: grow
          text "Derivatives" :: bold size(20) color(#fff)
          text "d/dx — Differentiation" :: size(12) color(#7B73A0)

    col :: pad(20) gap(16)

      // ── Input ─────────────────────────
      card :: pad(20) radius(14) bg(#1E1650) border(#2A2060)
        col :: gap(14)
          text "f(x) =" :: bold size(14) color(#7B73A0)
          input ~deriv_input :: pad(14) radius(10) bg(#0F0A2E) color(#fff) border(#2A2060) placeholder("e.g. 3x^2, sin(x), e^x")

          button "Calculate d/dx" :: pad(14) radius(10) bg(#7B5EFF) color(#fff) bold size(14) center
            => send(action: "derivative", expr: ~deriv_input)

      // ── Result ────────────────────────
      card :: pad(20) radius(14) bg(#16103A) border(#7B5EFF) glow(#7B5EFF) animate(fadeIn)
        col :: gap(10) center
          text "Result" :: size(12) color(#7B73A0)
          text "f'(x) =" :: bold size(14) color(#7B5EFF)
          text ~deriv_result :: bold size(22) color(#fff) animate(glow)

      // ── Quick Examples ────────────────
      card :: pad(16) radius(12) bg(#1E1650) border(#2A2060)
        col :: gap(10)
          text "Quick Examples" :: bold size(14) color(#fff)
          row :: gap(8)
            button "x^3" :: pad(8) radius(8) bg(#2A1F6E) color(#7B5EFF) size(12)
              => ~deriv_input = "x^3"
            button "5x^2" :: pad(8) radius(8) bg(#2A1F6E) color(#7B5EFF) size(12)
              => ~deriv_input = "5x^2"
            button "sin(x)" :: pad(8) radius(8) bg(#2A1F6E) color(#7B5EFF) size(12)
              => ~deriv_input = "sin(x)"
          row :: gap(8)
            button "cos(x)" :: pad(8) radius(8) bg(#2A1F6E) color(#7B5EFF) size(12)
              => ~deriv_input = "cos(x)"
            button "e^x" :: pad(8) radius(8) bg(#2A1F6E) color(#7B5EFF) size(12)
              => ~deriv_input = "e^x"
            button "ln(x)" :: pad(8) radius(8) bg(#2A1F6E) color(#7B5EFF) size(12)
              => ~deriv_input = "ln(x)"

      // ── Rules Reference ───────────────
      card :: pad(16) radius(12) bg(#1E1650) border(#2A2060)
        col :: gap(8)
          text "Differentiation Rules" :: bold size(14) color(#fff)
          text "(x^n)' = n*x^(n-1)" :: size(12) color(#7B5EFF)
          text "(sin x)' = cos x" :: size(12) color(#00F0FF)
          text "(cos x)' = -sin x" :: size(12) color(#00F0FF)
          text "(e^x)' = e^x" :: size(12) color(#FFD700)
          text "(ln x)' = 1/x" :: size(12) color(#FFD700)
          text "(tan x)' = 1/cos\\u00B2x" :: size(12) color(#FF4081)

// ══════════════════════════════════════════
//  Integral Calculator
// ══════════════════════════════════════════

@screen Integral

  ~integ_input = ""
  ~integ_result = ""

  col :: pad(0) gap(0) bg(#0F0A2E)

    col :: pad(20) gap(6) gradient(#1A1145-#0A2A30)
      row :: gap(12) center
        button "\\u2190" :: pad(8) radius(8) bg(#0A2A30) color(#00F0FF) size(16)
          => back()
        mathicon "integral" :: size(28) color(#00F0FF) animate(glow)
        col :: grow
          text "Integrals" :: bold size(20) color(#fff)
          text "\\u222B — Indefinite Integration" :: size(12) color(#7B73A0)

    col :: pad(20) gap(16)

      card :: pad(20) radius(14) bg(#1E1650) border(#2A2060)
        col :: gap(14)
          text "\\u222B f(x) dx" :: bold size(14) color(#7B73A0)
          input ~integ_input :: pad(14) radius(10) bg(#0F0A2E) color(#fff) border(#2A2060) placeholder("e.g. x^2, cos(x), 1/x")

          button "Integrate" :: pad(14) radius(10) bg(#00B8D4) color(#fff) bold size(14) center
            => send(action: "integral", expr: ~integ_input)

      card :: pad(20) radius(14) bg(#16103A) border(#00F0FF) glow(#00F0FF) animate(fadeIn)
        col :: gap(10) center
          text "Result" :: size(12) color(#7B73A0)
          text "F(x) =" :: bold size(14) color(#00F0FF)
          text ~integ_result :: bold size(22) color(#fff) animate(glow)

      card :: pad(16) radius(12) bg(#1E1650) border(#2A2060)
        col :: gap(10)
          text "Quick Examples" :: bold size(14) color(#fff)
          row :: gap(8)
            button "x^2" :: pad(8) radius(8) bg(#0A2A30) color(#00F0FF) size(12)
              => ~integ_input = "x^2"
            button "3x" :: pad(8) radius(8) bg(#0A2A30) color(#00F0FF) size(12)
              => ~integ_input = "3x"
            button "sin(x)" :: pad(8) radius(8) bg(#0A2A30) color(#00F0FF) size(12)
              => ~integ_input = "sin(x)"
          row :: gap(8)
            button "cos(x)" :: pad(8) radius(8) bg(#0A2A30) color(#00F0FF) size(12)
              => ~integ_input = "cos(x)"
            button "e^x" :: pad(8) radius(8) bg(#0A2A30) color(#00F0FF) size(12)
              => ~integ_input = "e^x"
            button "1/x" :: pad(8) radius(8) bg(#0A2A30) color(#00F0FF) size(12)
              => ~integ_input = "1/x"

      card :: pad(16) radius(12) bg(#1E1650) border(#2A2060)
        col :: gap(8)
          text "Integration Rules" :: bold size(14) color(#fff)
          text "\\u222B x^n dx = x^(n+1)/(n+1) + C" :: size(12) color(#00F0FF)
          text "\\u222B sin x dx = -cos x + C" :: size(12) color(#00F0FF)
          text "\\u222B cos x dx = sin x + C" :: size(12) color(#00F0FF)
          text "\\u222B e^x dx = e^x + C" :: size(12) color(#FFD700)
          text "\\u222B 1/x dx = ln|x| + C" :: size(12) color(#FFD700)

// ══════════════════════════════════════════
//  Quadratic Equations
// ══════════════════════════════════════════

@screen Equations

  ~eq_a = ""
  ~eq_b = ""
  ~eq_c = ""
  ~quad_result = ""

  col :: pad(0) gap(0) bg(#0F0A2E)

    col :: pad(20) gap(6) gradient(#1A1145-#2A2500)
      row :: gap(12) center
        button "\\u2190" :: pad(8) radius(8) bg(#2A2500) color(#FFD700) size(16)
          => back()
        mathicon "equation" :: size(28) color(#FFD700) animate(glow)
        col :: grow
          text "Equations" :: bold size(20) color(#fff)
          text "ax\\u00B2 + bx + c = 0" :: size(12) color(#7B73A0)

    col :: pad(20) gap(16)

      card :: pad(20) radius(14) bg(#1E1650) border(#2A2060)
        col :: gap(14)
          text "Quadratic Equation Solver" :: bold size(15) color(#fff)
          text "Enter coefficients a, b, c:" :: size(12) color(#7B73A0)
          row :: gap(10)
            col :: gap(4) grow
              text "a" :: size(12) color(#FFD700) center
              input ~eq_a :: pad(12) radius(8) bg(#0F0A2E) color(#fff) border(#2A2060) placeholder("a")
            col :: gap(4) grow
              text "b" :: size(12) color(#FFD700) center
              input ~eq_b :: pad(12) radius(8) bg(#0F0A2E) color(#fff) border(#2A2060) placeholder("b")
            col :: gap(4) grow
              text "c" :: size(12) color(#FFD700) center
              input ~eq_c :: pad(12) radius(8) bg(#0F0A2E) color(#fff) border(#2A2060) placeholder("c")

          button "Solve" :: pad(14) radius(10) bg(#FFD700) color(#0F0A2E) bold size(14) center
            => send(action: "quadratic", a: ~eq_a, b: ~eq_b, c: ~eq_c)

      card :: pad(20) radius(14) bg(#16103A) border(#FFD700) glow(#FFD700) animate(fadeIn)
        col :: gap(10) center
          text "Solution" :: size(12) color(#7B73A0)
          text ~quad_result :: bold size(18) color(#fff) animate(glow)

      // ── Preset examples ───────────────
      card :: pad(16) radius(12) bg(#1E1650) border(#2A2060)
        col :: gap(10)
          text "Try These" :: bold size(14) color(#fff)
          row :: gap(8)
            button "x\\u00B2-5x+6" :: pad(8) radius(8) bg(#2A2500) color(#FFD700) size(12)
              => ~eq_a = "1"; ~eq_b = "-5"; ~eq_c = "6"
            button "x\\u00B2+1" :: pad(8) radius(8) bg(#2A2500) color(#FFD700) size(12)
              => ~eq_a = "1"; ~eq_b = "0"; ~eq_c = "1"
            button "2x\\u00B2-8" :: pad(8) radius(8) bg(#2A2500) color(#FFD700) size(12)
              => ~eq_a = "2"; ~eq_b = "0"; ~eq_c = "-8"

      card :: pad(16) radius(12) bg(#1E1650) border(#2A2060)
        col :: gap(8)
          text "Quadratic Formula" :: bold size(14) color(#fff)
          text "x = (-b \\u00B1 \\u221AD) / 2a" :: size(14) color(#FFD700)
          text "D = b\\u00B2 - 4ac" :: size(13) color(#7B73A0)
          divider
          text "D > 0 \\u2192 two real roots" :: size(12) color(#00E676)
          text "D = 0 \\u2192 one root" :: size(12) color(#FFD700)
          text "D < 0 \\u2192 complex roots" :: size(12) color(#FF4081)

// ══════════════════════════════════════════
//  Matrix Calculator (2x2)
// ══════════════════════════════════════════

@screen Matrix

  ~m_a = ""
  ~m_b = ""
  ~m_c = ""
  ~m_d = ""
  ~mat_det = ""
  ~mat_trace = ""

  col :: pad(0) gap(0) bg(#0F0A2E)

    col :: pad(20) gap(6) gradient(#1A1145-#0A2A15)
      row :: gap(12) center
        button "\\u2190" :: pad(8) radius(8) bg(#0A2A15) color(#00E676) size(16)
          => back()
        mathicon "matrix" :: size(28) color(#00E676) animate(glow)
        col :: grow
          text "Matrices" :: bold size(20) color(#fff)
          text "2\\u00D72 Matrix Operations" :: size(12) color(#7B73A0)

    col :: pad(20) gap(16)

      card :: pad(20) radius(14) bg(#1E1650) border(#2A2060)
        col :: gap(14)
          text "Enter Matrix Elements" :: bold size(15) color(#fff)
          text "| a  b |" :: size(13) color(#00E676) center
          text "| c  d |" :: size(13) color(#00E676) center

          row :: gap(10)
            col :: gap(4) grow
              text "a" :: size(11) color(#00E676) center
              input ~m_a :: pad(12) radius(8) bg(#0F0A2E) color(#fff) border(#2A2060) placeholder("a")
            col :: gap(4) grow
              text "b" :: size(11) color(#00E676) center
              input ~m_b :: pad(12) radius(8) bg(#0F0A2E) color(#fff) border(#2A2060) placeholder("b")
          row :: gap(10)
            col :: gap(4) grow
              text "c" :: size(11) color(#00E676) center
              input ~m_c :: pad(12) radius(8) bg(#0F0A2E) color(#fff) border(#2A2060) placeholder("c")
            col :: gap(4) grow
              text "d" :: size(11) color(#00E676) center
              input ~m_d :: pad(12) radius(8) bg(#0F0A2E) color(#fff) border(#2A2060) placeholder("d")

          button "Calculate" :: pad(14) radius(10) bg(#00E676) color(#0F0A2E) bold size(14) center
            => send(action: "determinant", a: ~m_a, b: ~m_b, c: ~m_c, d: ~m_d)

      row :: gap(12)
        card :: pad(16) radius(12) bg(#16103A) border(#00E676) grow glow(#00E676) animate(fadeIn)
          col :: gap(6) center
            text "det(A)" :: size(12) color(#7B73A0)
            text ~mat_det :: bold size(24) color(#00E676) animate(glow)
        card :: pad(16) radius(12) bg(#16103A) border(#00E676) grow glow(#00E676) animate(fadeIn)
          col :: gap(6) center
            text "tr(A)" :: size(12) color(#7B73A0)
            text ~mat_trace :: bold size(24) color(#00E676) animate(glow)

      card :: pad(16) radius(12) bg(#1E1650) border(#2A2060)
        col :: gap(8)
          text "Formulas" :: bold size(14) color(#fff)
          text "det(A) = ad - bc" :: size(12) color(#00E676)
          text "tr(A) = a + d" :: size(12) color(#00E676)
          text "A\\u207B\\u00B9 = (1/det) * adj(A)" :: size(12) color(#7B73A0)

// ══════════════════════════════════════════
//  Limits
// ══════════════════════════════════════════

@screen Limits

  ~lim_expr = ""
  ~lim_point = ""
  ~limit_result = ""

  col :: pad(0) gap(0) bg(#0F0A2E)

    col :: pad(20) gap(6) gradient(#1A1145-#2A0A20)
      row :: gap(12) center
        button "\\u2190" :: pad(8) radius(8) bg(#2A0A20) color(#FF4081) size(16)
          => back()
        mathicon "limit" :: size(28) color(#FF4081) animate(glow)
        col :: grow
          text "Limits" :: bold size(20) color(#fff)
          text "lim f(x) as x\\u2192a" :: size(12) color(#7B73A0)

    col :: pad(20) gap(16)

      card :: pad(20) radius(14) bg(#1E1650) border(#2A2060)
        col :: gap(14)
          text "Calculate Limit" :: bold size(15) color(#fff)
          text "f(x) =" :: size(12) color(#7B73A0)
          input ~lim_expr :: pad(14) radius(10) bg(#0F0A2E) color(#fff) border(#2A2060) placeholder("e.g. sin(x)/x")
          text "x \\u2192" :: size(12) color(#7B73A0)
          input ~lim_point :: pad(14) radius(10) bg(#0F0A2E) color(#fff) border(#2A2060) placeholder("e.g. 0, inf")

          button "Find Limit" :: pad(14) radius(10) bg(#FF4081) color(#fff) bold size(14) center
            => send(action: "limit", expr: ~lim_expr, point: ~lim_point)

      card :: pad(20) radius(14) bg(#16103A) border(#FF4081) glow(#FF4081) animate(fadeIn)
        col :: gap(10) center
          text "Result" :: size(12) color(#7B73A0)
          text "L =" :: bold size(14) color(#FF4081)
          text ~limit_result :: bold size(22) color(#fff) animate(glow)

      card :: pad(16) radius(12) bg(#1E1650) border(#2A2060)
        col :: gap(10)
          text "Famous Limits" :: bold size(14) color(#fff)
          row :: gap(8)
            button "sin(x)/x" :: pad(8) radius(8) bg(#2A0A20) color(#FF4081) size(11)
              => ~lim_expr = "sin(x)/x"; ~lim_point = "0"
            button "(1+1/x)^x" :: pad(8) radius(8) bg(#2A0A20) color(#FF4081) size(11)
              => ~lim_expr = "(1+1/x)^x"; ~lim_point = "inf"
          row :: gap(8)
            button "(e^x-1)/x" :: pad(8) radius(8) bg(#2A0A20) color(#FF4081) size(11)
              => ~lim_expr = "(e^x-1)/x"; ~lim_point = "0"
            button "ln(x)/x" :: pad(8) radius(8) bg(#2A0A20) color(#FF4081) size(11)
              => ~lim_expr = "ln(x)/x"; ~lim_point = "inf"

      card :: pad(16) radius(12) bg(#1E1650) border(#2A2060)
        col :: gap(8)
          text "Key Limits" :: bold size(14) color(#fff)
          text "lim sin(x)/x = 1  (x\\u21920)" :: size(12) color(#FF4081)
          text "lim (1+1/x)^x = e  (x\\u2192\\u221E)" :: size(12) color(#FF4081)
          text "lim (e^x-1)/x = 1  (x\\u21920)" :: size(12) color(#FFD700)
          text "lim ln(x)/x = 0  (x\\u2192\\u221E)" :: size(12) color(#FFD700)

// ══════════════════════════════════════════
//  Reference — Formulas & Tables
// ══════════════════════════════════════════

@screen Reference

  col :: pad(0) gap(0) bg(#0F0A2E)

    col :: pad(20) gap(6) gradient(#1A1145-#2A1A00)
      row :: gap(12) center
        button "\\u2190" :: pad(8) radius(8) bg(#2A1A00) color(#FF9100) size(16)
          => back()
        mathicon "sigma" :: size(28) color(#FF9100) animate(glow)
        col :: grow
          text "Reference" :: bold size(20) color(#fff)
          text "Formulas & Identities" :: size(12) color(#7B73A0)

    col :: pad(20) gap(14)

      card :: pad(18) radius(14) bg(#1E1650) border(#2A2060)
        col :: gap(10)
          text "Trigonometric Identities" :: bold size(15) color(#FF9100)
          divider
          text "sin\\u00B2(x) + cos\\u00B2(x) = 1" :: size(13) color(#E8E0FF)
          text "1 + tan\\u00B2(x) = sec\\u00B2(x)" :: size(13) color(#E8E0FF)
          text "sin(2x) = 2 sin(x) cos(x)" :: size(13) color(#E8E0FF)
          text "cos(2x) = cos\\u00B2(x) - sin\\u00B2(x)" :: size(13) color(#E8E0FF)
          text "tan(x) = sin(x) / cos(x)" :: size(13) color(#E8E0FF)

      card :: pad(18) radius(14) bg(#1E1650) border(#2A2060)
        col :: gap(10)
          text "Power & Log Rules" :: bold size(15) color(#7B5EFF)
          divider
          text "a^m * a^n = a^(m+n)" :: size(13) color(#E8E0FF)
          text "(a^m)^n = a^(m*n)" :: size(13) color(#E8E0FF)
          text "log(ab) = log(a) + log(b)" :: size(13) color(#E8E0FF)
          text "log(a/b) = log(a) - log(b)" :: size(13) color(#E8E0FF)
          text "log(a^n) = n * log(a)" :: size(13) color(#E8E0FF)

      card :: pad(18) radius(14) bg(#1E1650) border(#2A2060)
        col :: gap(10)
          text "Taylor Series" :: bold size(15) color(#00F0FF)
          divider
          text "e^x = 1 + x + x\\u00B2/2! + x\\u00B3/3! + ..." :: size(13) color(#E8E0FF)
          text "sin(x) = x - x\\u00B3/3! + x\\u2075/5! - ..." :: size(13) color(#E8E0FF)
          text "cos(x) = 1 - x\\u00B2/2! + x\\u2074/4! - ..." :: size(13) color(#E8E0FF)
          text "ln(1+x) = x - x\\u00B2/2 + x\\u00B3/3 - ..." :: size(13) color(#E8E0FF)

      card :: pad(18) radius(14) bg(#1E1650) border(#2A2060)
        col :: gap(10)
          text "Constants" :: bold size(15) color(#00E676)
          divider
          row :: gap(12)
            text "\\u03C0" :: bold size(18) color(#00E676)
            text "= 3.14159265..." :: size(13) color(#E8E0FF)
          row :: gap(12)
            text "e" :: bold size(18) color(#00E676)
            text "= 2.71828182..." :: size(13) color(#E8E0FF)
          row :: gap(12)
            text "\\u03C6" :: bold size(18) color(#00E676)
            text "= 1.61803398... (golden ratio)" :: size(13) color(#E8E0FF)
          row :: gap(12)
            text "\\u221A2" :: bold size(18) color(#00E676)
            text "= 1.41421356..." :: size(13) color(#E8E0FF)
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
