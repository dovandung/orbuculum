// Orbuculum line counts: shows, in front of every source line, how many times it ran.
// The numbers come from the lcov file that orbprofile -c writes (and -l keeps rewriting).
//
// Install: copy this folder to %USERPROFILE%\.vscode\extensions\orb-line-counts and restart VS Code.
const fs = require('fs');
const path = require('path');

const WIDTH = 7;                       // characters reserved in front of each line
const NBSP = '\u00a0';

// ---- Pure functions (no VS Code needed, so they can be tested with node) ------------------------

/** Same file, however its path is spelled: D:\a\b//c.C and d:/a/b/c.c */
function normalise(p) {
    return p.replace(/\\/g, '/').replace(/\/{2,}/g, '/').toLowerCase();
}

/** lcov text -> Map(normalised file name -> Map(line number -> count)) */
function parseLcov(text) {
    const files = new Map();
    let lines = null;
    for (const row of text.split(/\r?\n/)) {
        if (row.startsWith('SF:')) {
            const name = normalise(row.slice(3).trim());
            lines = files.get(name);
            if (!lines) { lines = new Map(); files.set(name, lines); }
        } else if (row.startsWith('DA:') && lines) {
            const c = row.slice(3).split(',');
            const line = parseInt(c[0], 10);
            const count = Number(c[1]);
            if (line > 0 && isFinite(count)) {
                lines.set(line, Math.max(count, lines.get(line) || 0));
            }
        } else if (row === 'end_of_record') {
            lines = null;
        }
    }
    return files;
}

/** 0, 1 .. 99999 exactly, then 123k, 4.56M, 78.9M, 1.23G: never more than six characters */
function formatCount(n) {
    if (n < 100000) { return String(n); }
    const units = [[1e12, 'T'], [1e9, 'G'], [1e6, 'M'], [1e3, 'k']];
    for (const [size, letter] of units) {
        if (n >= size) {
            const v = n / size;
            return (v >= 100 ? Math.floor(v).toString() : v >= 10 ? (Math.floor(v * 10) / 10).toFixed(1) : (Math.floor(v * 100) / 100).toFixed(2)) + letter;
        }
    }
    return String(n);
}

function pad(text) {
    return NBSP.repeat(Math.max(WIDTH - 1 - text.length, 0)) + text + NBSP;
}

module.exports = { normalise, parseLcov, formatCount, pad };

// ---- The extension -----------------------------------------------------------------------------

module.exports.activate = function (context) {
    const vscode = require('vscode');
    let files = new Map();             // what the coverage file says
    let stamp = '';                    // its size and time when last read
    let shown = vscode.workspace.getConfiguration('orbLineCounts').get('enabled', true);

    const decoration = vscode.window.createTextEditorDecorationType({});
    const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 0);
    status.command = 'orbLineCounts.toggle';
    context.subscriptions.push(decoration, status);

    function coverageFile() {
        const name = vscode.workspace.getConfiguration('orbLineCounts').get('coverageFile', 'coverage.info');
        if (path.isAbsolute(name)) { return name; }
        const folders = vscode.workspace.workspaceFolders;
        return folders && folders.length ? path.join(folders[0].uri.fsPath, name) : null;
    }

    function draw(editor) {
        if (!editor) { return; }
        const lines = shown ? files.get(normalise(editor.document.uri.fsPath)) : null;
        if (!lines) {
            editor.setDecorations(decoration, []);
            return;
        }
        const grey = new vscode.ThemeColor('editorLineNumber.foreground');
        const never = new vscode.ThemeColor('editorError.foreground');
        const options = [];
        for (let i = 0; i < editor.document.lineCount; i++) {
            const count = lines.get(i + 1);
            const start = new vscode.Position(i, 0);
            options.push({
                range: new vscode.Range(start, start),
                hoverMessage: count === undefined ? undefined : (count ? 'Ran ' + count.toLocaleString() + ' times' : 'Did not run during this capture'),
                renderOptions: {
                    before: {
                        // Every line gets the same width, so the code stays lined up
                        contentText: count === undefined ? NBSP.repeat(WIDTH) : pad(formatCount(count)),
                        color: count === 0 ? never : grey,
                        fontStyle: 'normal'
                    }
                }
            });
        }
        editor.setDecorations(decoration, options);
    }

    function drawAll() {
        vscode.window.visibleTextEditors.forEach(draw);
        const editor = vscode.window.activeTextEditor;
        const here = editor && files.get(normalise(editor.document.uri.fsPath));
        status.text = !files.size ? '$(list-ordered) Counts: no data' : !shown ? '$(list-ordered) Counts: off'
            : here ? '$(list-ordered) Counts: on' : '$(list-ordered) Counts: not this file';
        status.tooltip = 'Orbuculum line counts from ' + (coverageFile() || 'coverage.info') + ' (click to show or hide)';
        status.show();
    }

    function reload() {
        const file = coverageFile();
        if (!file) { return; }
        fs.stat(file, (err, st) => {
            if (err) {
                if (files.size) { files = new Map(); stamp = ''; drawAll(); }
                return;
            }
            const now = st.size + ':' + st.mtimeMs;
            if (now === stamp) { return; }
            fs.readFile(file, 'utf8', (err2, text) => {
                if (err2) { return; }          // orbprofile is replacing it this instant: next time
                stamp = now;
                files = parseLcov(text);
                drawAll();
            });
        });
    }

    context.subscriptions.push(
        vscode.commands.registerCommand('orbLineCounts.toggle', () => { shown = !shown; drawAll(); }),
        vscode.window.onDidChangeActiveTextEditor(drawAll),
        vscode.window.onDidChangeVisibleTextEditors(drawAll),
        vscode.workspace.onDidChangeConfiguration(e => {
            if (e.affectsConfiguration('orbLineCounts')) { stamp = ''; reload(); }
        })
    );

    // orbprofile -l rewrites the file about once a second; looking that often is cheap
    const timer = setInterval(reload, 1000);
    context.subscriptions.push({ dispose: () => clearInterval(timer) });
    reload();
    drawAll();
};

module.exports.deactivate = function () { };
