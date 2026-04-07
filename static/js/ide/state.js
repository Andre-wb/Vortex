// ── State ─────────────────────────────────────────────────────
const IDE = {
    projects:        [],     // all projects
    current:         null,   // current project object
    openFiles:       [],     // open tab names
    activeFile:      null,   // "path/filename.grav"
    simVisible:      false,
    docsVisible:     false,
    newFileIsDir:    false,
    newFileParent:   null,   // folder name when creating inside a folder
    expandedFolders: new Set(),
    ctxFolder:       null,   // folder name that context menu is open for
    consoleTab:      'output',
};

const STORAGE_KEY = 'gx_projects_v1';

// ── Init ──────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    ideLoad();
    ideRenderDocs();
});

function ideLoad() {
    try { IDE.projects = JSON.parse(localStorage.getItem(STORAGE_KEY)) || []; }
    catch { IDE.projects = []; }
    ideRenderHub();
}

function ideSave() {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(IDE.projects));
}
