// ══════════════════════════════════════════════════════════════
//  Gravitix IDE  — entry point
//  All logic is in static/js/ide/ subfolder, loaded before this.
// ══════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
    ideLoad();
    ideRenderDocs();
});
