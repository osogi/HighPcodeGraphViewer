
# High P-Code Graph Viewer

An experimental Ghidra plugin for research and reverse engineering. It adds a dedicated window visualizing the **High P-code graph** for the current function, with interactive highlighting synchronized to the Decompiler.

The graph displays a **Control Flow Graph (CFG)** of basic blocks, each containing the associated **Data Flow Graph (DFG)** of varnodes and p-nodes. When you select a pseudo-C statement in the Decompiler window, the corresponding High P-code operations are automatically highlighted.

![Peek 2026-02-28 16-00](https://github.com/user-attachments/assets/ea7e762c-0a81-476b-9468-645681140ecf)

---

## Requirements

- Ghidra (tested on 12.0))
- [JDK 21 64-bit](https://adoptium.net/temurin/releases)

For build:
- gradle 8.7+

---

## Build

```bash
gradle -PGHIDRA_INSTALL_DIR=<absolute/path/to/ghidra> #This produces the extension ZIP in `dist/`.
````

---

## Installation

1. **Open the Project window** (not CodeBrowser)
    - `File → Install Extensions...`
    - Click `Add Extension` and select the built (or downloaded) ZIP file
2. **Restart Ghidra**
3. **Enable in CodeBrowser**
    - `File → Configure... → Experimental [Configure]`
    - Check `HighPcodeGraphViewerPlugin`

---

## Usage

1. Open a function in the CodeBrowser
2. Right-click in the decompiler view → **"Show High P-code Graph"**
