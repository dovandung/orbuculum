# Trace beside the debugger in VS Code

These three files go in the `.vscode` folder of a firmware project. They let a normal debug
session (Cortex-Debug with an ST-LINK or J-Link) run while a trace probe listens on the trace
pins, and connect the two:

| What | How |
|---|---|
| What ran just before a halt | `Trace: history (orbmortem)` task; in the debug console `trace-back`, `trace-calls` |
| Jump from a trace line to the source | `O` on a line in orbmortem |
| Coverage shown in the editor, live | `Trace: live coverage` task and the Coverage Gutters extension |
| printf output | `Trace: ITM console` task |
| Function timeline | `Trace: timeline` task, open `timeline.json` at ui.perfetto.dev |

## Setting up

1. Install the VS Code extensions **Cortex-Debug** (`marus25.cortex-debug`) and
   **Coverage Gutters** (`ryanluker.vscode-coverage-gutters`).
2. Copy `settings.json`, `tasks.json` and `launch.json` into `<project>/.vscode/`.
3. In `tasks.json` set the three paths under `options.env` and the default ELF/AXF under `inputs`.
4. In `launch.json` keep the configuration for your debug probe, and set `executable`, `device`
   and the path of `orbtrace_gdb.py`.
5. The gdb commands need an `arm-none-eabi-gdb` built with Python. If `source ...orbtrace_gdb.py`
   fails with "Python scripting is not supported", remove the three `postAttachCommands` lines;
   everything else still works.

## Using it

1. **Terminal > Run Task > Trace: start (probe + hub)**.
2. Run **Trace: history (orbmortem)**. It shows nothing while the program runs.
3. Start debugging (F5) with an "Attach + trace" configuration.
4. When the program stops at a breakpoint, the orbmortem panel shows the instructions that led
   there, and the debug console prints the last ten source lines (`trace-auto 10`). Type
   `trace-back 50` or `trace-calls` in the debug console for more. The `file:line` texts are links.
5. For coverage, run **Trace: live coverage** instead of orbmortem, click **Watch** in the status
   bar, and exercise the board: executed lines turn green in the editor.

The debugger must leave the trace pins alone: the firmware (or a gdb script such as
`gdbtrace.init`) switches trace on, and trace is off in the debugger's own settings.

orbmortem and orbprofile both decode the ETM stream; run one of them at a time if the PC is
short of CPU.
