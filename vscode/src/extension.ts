import * as vscode from "vscode";
import { spawn, ChildProcessWithoutNullStreams } from "child_process";
import * as path from "path";
import * as os from 'os';
import WebSocket from "ws";

import * as fs from "fs";
import * as crypto from "crypto";

const logFilePath = path.join(os.tmpdir(), 'dzdbgport.log');

class DayZDebugPort {
    tcpPort: number;
    loadedFiles: Set<string>;
    pid: number;
    peerType: string;

    constructor(
        tcpPort: number,
        pid: number,
        peerType: string,
        loadedFiles: Iterable<string> = [],
    ) {
        this.tcpPort = tcpPort;
        this.loadedFiles = new Set(loadedFiles);
        this.pid = pid;
        this.peerType = peerType;
    }

    addFile(file: string): void {
        this.loadedFiles.add(file);
    }

    removeFile(file: string): void {
        this.loadedFiles.delete(file);
    }

    info(): string {
        return `PID: ${this.pid}, Port: ${this.tcpPort}, Type: ${this.peerType}, Loaded Files Count: ${this.loadedFiles.size}`;
    }

    displayPeerType(): string {
        if (this.peerType === "S")
            return "Server";
        if (this.peerType === "C")
            return "Client";
        return this.peerType;
    }
    logPeerType(): string {
        if (this.peerType === "S")
            return " S";
        if (this.peerType === "C")
            return "C ";
        return this.peerType;
    }
}


let socket: WebSocket | null = null;
let outputChannel: vscode.OutputChannel;
let gameLogChannel: vscode.OutputChannel;
let execCodeViewProvider: ExecCodeViewProvider;
let decorationProvider: LoadedFileDecorationProvider;
let statusBarItem: vscode.StatusBarItem;
const loadedFiles = new Map<string, number>();
const ports = new Map<number, DayZDebugPort>();
let selectedPort = -1;
let activeConnectPromise: Promise<boolean> | null = null;

let isDisconnecting = false;
let disconnectTimeout: NodeJS.Timeout | null = null;

function logPlugin(msg: string, end: string = "\n") {
    outputChannel.append(`[plugin ] ${msg}${end}`)
}

function logPort(msg: string, end: string = "\n") {
    outputChannel.append(`[dbgport] ${msg}${end}`)
}

function clearData(): void {
    ports.clear();
    loadedFiles.clear();
    decorationProvider.notifyChange();
    logPlugin("[WS] Cleared data");
}

interface PluginConfig {
    dataPath: string;
    enableDebugPort: boolean;
}

function pluginConfig(): PluginConfig {
    const config = vscode.workspace.getConfiguration("dzdbgport");
    return {
        dataPath:        config.get<string>("dataPath", "P:\\")!,
        enableDebugPort: config.get<boolean>("enableDebugPort", true)!,
    };
}

function showNotification(message: string, duration: number) {
  vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification },
    async (progress) => {
      const steps = 100;
      const delay = duration / steps;

      for (let i = 0; i <= steps; i++) {
        await new Promise<void>((resolve) => {
          setTimeout(() => {
            progress.report({ increment: 1, message: message });
            resolve();
          }, delay);
        });
      }
    }
  );
}

function updateStatusBarItem() {
    const enabled = pluginConfig().enableDebugPort;

    if (!enabled) {
        statusBarItem.text = "🔴 DayZ (Off)";
        statusBarItem.tooltip = "Click to enable DayZ Debug Port";
        statusBarItem.command = "dzdbgport.toggleDebugPort";
    } else if (ports.size) {
        let port = ports.get(selectedPort);
        if (port) {
            if (ports.size == 1)
                statusBarItem.text = `🟢 DayZ ${ports.size} port (${port.displayPeerType()}, PID ${port.pid})`;
            else
                statusBarItem.text = `🟢 DayZ ${ports.size} ports (${port.displayPeerType()}, PID ${port.pid})`;
        }
        else
            statusBarItem.text = `🟢 DayZ ${ports.size} ports`;
        statusBarItem.tooltip = "Click to choose target DayZ Debug Port";
        statusBarItem.command = "dzdbgport.selectTargetPort";
    } else {
        statusBarItem.text = `🟡 DayZ ${ports.size} ports`;
        statusBarItem.tooltip = "Click to choose target DayZ Debug Port (No Game Connected)";
        statusBarItem.command = "dzdbgport.selectTargetPort";
    }

    
}

function updateStatusBarVisibility() {

    // if any instance is connected, always show
    if (ports.size) {
        statusBarItem.show();
        return;
    }

    const editor = vscode.window.activeTextEditor;
    const supportedLanguages = ["c", "enscript", "des"];

    const isSupportedFile = editor && supportedLanguages.includes(editor.document.languageId);

    if (isSupportedFile) {
        statusBarItem.show();
    } else {
        statusBarItem.hide();
    }
}

async function pickTargetPort(): Promise<void> {
    if (!pluginConfig().enableDebugPort) {
        await toggleDebugPort();
        return;
    }

    const allPorts = [...ports.values()]
        .sort((a, b) => a.tcpPort - b.tcpPort);

    // If we already have a selected port, put it first
    const sorted = selectedPort !== -1
        ? allPorts.sort((a, b) => {
            if (a.tcpPort === selectedPort) return -1;
            if (b.tcpPort === selectedPort) return 1;
            return a.tcpPort - b.tcpPort;
        })
        : allPorts;

    const items = sorted.map(p => ({
        label: `PID ${p.pid}`,
        description: `${p.displayPeerType()}`,
        value: p.tcpPort
    }));

    const picked = await vscode.window.showQuickPick(items, {
        title: "Select Target Port",
        placeHolder: "Choose the DayZ target port",
        matchOnDescription: true,
        canPickMany: false
    });

    if (!picked) return;

    selectedPort = picked.value;
    updateStatusBarItem();
    updateExecButtonState();

    let port = ports.get(selectedPort);
    if (port)
        showNotification(`🎯 Selected port PID ${port.pid} (${port.displayPeerType()})`, 5000);
}


function webviewPostMessage(message: any) {
    if (execCodeViewProvider && execCodeViewProvider.view) {
        execCodeViewProvider.view.webview.postMessage(message);
    }
}

function updateExecButtonState() {
    const enabled = (socket && socket.readyState === WebSocket.OPEN && ports.get(selectedPort));
    webviewPostMessage({ type: "executeEnabled", enabled: enabled });
}

async function cleanupOrphanProcesses(): Promise<void> {
    return new Promise((resolve) => {
        const killer = spawn("taskkill", ["/IM", "dzdbgport.exe", "/F", "/T"]);
        killer.on("exit", () => {
            logPlugin(`[INFO] taskkill complete.`);
            resolve();
        });

        killer.on("error", (err) => {
            logPlugin(`[ERROR] Failed to run taskkill: ${err.message}`);
            resolve();
        });
    });
}

function ensureDir(p: string) {
    if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
}

function sha1File(p: string): string {
    const h = crypto.createHash("sha1");
    h.update(fs.readFileSync(p));
    return h.digest("hex");
}

function ensureLocalBinary(context: vscode.ExtensionContext): string {
    const srcExe = path.join(context.extensionPath, "bin", "dzdbgport.exe");
    const dstDir = path.join(context.globalStorageUri.fsPath, "bin");
    const dstExe = path.join(dstDir, "dzdbgport.exe");

    ensureDir(dstDir);

    let needCopy = !fs.existsSync(dstExe);
    if (!needCopy) {
        try {
            needCopy = sha1File(srcExe) !== sha1File(dstExe);
        } catch {
            needCopy = true;
        }
    }

    if (needCopy) {
        try {
            (async () => { await cleanupOrphanProcesses(); })();
        } catch {}

        fs.copyFileSync(srcExe, dstExe);
        try { fs.chmodSync(dstExe, 0o755); } catch {}
    }

    return dstExe;
}

function sendWebSocketMessage(msg: any): boolean {
    if (socket && socket.readyState === socket.OPEN) {
        socket.send(JSON.stringify(msg));
        return true;
    }

    return false;
}

function selectNextPort() {
    selectedPort = ports.keys().next().value ?? -1;
}

function addLoadedFile(file: string) {
    const current = loadedFiles.get(file);
    if (!current)
        loadedFiles.set(file, 1)
    else
        loadedFiles.set(file, current + 1)
}

function removeLoadedFile(file: string) {
    const current = loadedFiles.get(file);
    if (!current || current < 2)
        loadedFiles.delete(file)
    else
        loadedFiles.set(file, current - 1)
}

function removePort(port: DayZDebugPort) {
    if (!ports.delete(port.tcpPort))
        return;

    for (const file of port.loadedFiles) {
        removeLoadedFile(file);
    }

    if (selectedPort === port.tcpPort)
        selectNextPort();
}

function addPort(port: DayZDebugPort) {
    let old_port = ports.get(port.tcpPort)
    if (old_port) {
        logPlugin(`[WS] Game port already connected (tcpPort: ${old_port.tcpPort})`);
        removePort(old_port);
    }

    for (const file of port.loadedFiles) {
        addLoadedFile(file);
    }

    ports.set(port.tcpPort, port);

    if (selectedPort === -1)
        selectNextPort();
}

function onWebSocketMessage(msg: any) {
    if (msg.type === "connect") {
        let port = new DayZDebugPort(
            msg.tcp_port ?? msg.pid,
            msg.pid,
            msg.peer_type ?? "C"
        )

        addPort(port);

        logPlugin(`[WS] Game connected (${port.displayPeerType()}, TCP:${port.tcpPort}, PID:${port.pid})`);

        updateExecButtonState();
        updateStatusBarItem();
        updateStatusBarVisibility();

        showNotification(`🟢 DayZ Game Connected (${port.displayPeerType()}, PID: ${port.pid})`, 5000);
    } else if (msg.type === "disconnect") {
        let tcpPort = msg.tcp_port ?? msg.pid;
        logPlugin(`[WS] Game disconnected (pid: ${msg.pid}, tcpPort: ${tcpPort}, reason: ${msg.reason})`);

        let port = ports.get(tcpPort);
        if (port)
        {
            removePort(port)
        }
        updateExecButtonState();
        updateStatusBarItem();
        updateStatusBarVisibility();

        if (msg.reason === "exit") {
            showNotification(`🟡 DayZ Game Disconnected (PID: ${msg.pid})`, 5000);
        }
        else if (msg.reason === "crash") {
            showNotification(`🔴 DayZ Game Crashed (PID: ${msg.pid})`, 5000);
        }
        else {
            showNotification(`🔴 DayZ Game Unknown Exit Reason (PID: ${msg.pid}, Reason: ${msg.reason})`, 5000);
        }
    }
    else if (msg.type === "block_load") {
        if (msg.filenames.length === 1 && msg.filenames[0] === "execCode") {
            logPlugin(`[WS] Code executed successfully (id 0x${msg.block_id.toString(16)})`);
            return;
        }

        let tcpPort = msg.tcp_port ?? selectedPort;

        logPlugin(`[WS] Block loaded (tcpPort ${tcpPort} id 0x${msg.block_id.toString(16)}, ${msg.filenames.length} files)`)

        let port = ports.get(tcpPort);
        if (!port) {
            logPlugin(`[WS] WARNING: Invalid port ${tcpPort}`)
            return;
        }

        for (const file of msg.filenames) {
            port.addFile(file)
            addLoadedFile(file);
        }

        decorationProvider.notifyChange();
    }
    else if (msg.type === "block_unload") {
        if (msg.filenames.length === 1 && msg.filenames[0] === "execCode") {
            return;
        }

        let tcpPort = msg.tcp_port ?? selectedPort;

        logPlugin(`[WS] Block unloaded (tcpPort ${tcpPort} id 0x${msg.block_id.toString(16)}, ${msg.filenames.length} files)`)

        let port = ports.get(tcpPort);
        if (!port) {
            logPlugin(`[WS] WARNING: Invalid port ${tcpPort}`)
            return;
        }

        for (const file of msg.filenames) {
            port.removeFile(file);
            removeLoadedFile(file);
        }
        decorationProvider.notifyChange();
    }
    else if (msg.type === "log") {
        let prefix = ""
        const text = msg.data;

        let port = ports.get(msg.tcp_port);
        if (port) {
            prefix = `[${String(port.pid).padEnd(5, "")} ${port.logPeerType()}] `
        }

        gameLogChannel.append(prefix + (text.endsWith('\n') ? text : text + '\n'));
    }
    else if (msg.type === "output") {
        const text = msg.data;
        text.split(/\r?\n/).forEach((line: string) => {
            if (line.trim() !== "") {
                logPort(line);
            }
        });
    }
    else {
        logPlugin(`[WS] [WARN] Unknown message type ${msg.type}`)
    }
}

function tryConnectWebSocket(maxWaitMs: number): Promise<boolean> {
    if (activeConnectPromise) return activeConnectPromise; // don't overlap
    const wsUrl = "ws://localhost:28051";
    let startTime = Date.now();

    activeConnectPromise = new Promise((resolve) => {
        function tryConnect() {
            if (Date.now() - startTime > maxWaitMs) {
                logPlugin("[WS] Failed to connect within timeout.");
                activeConnectPromise = null;
                return resolve(false);
            }

            const ws = new WebSocket(wsUrl);

            ws.onopen = () => {
                logPlugin("[WS] Connected to server.");
                socket = ws;
                clearData();
                updateExecButtonState();
                updateStatusBarItem();
                updateStatusBarVisibility();

                ws.onmessage = (event) => {
                    const raw = event.data;
                    const text = typeof raw === "string" ? raw : raw.toString();
                    const msg = JSON.parse(text);
                    onWebSocketMessage(msg);
                };

                ws.onclose = () => {
                    socket = null;
                    clearData();
                    updateExecButtonState();
                    updateStatusBarItem();
                    updateStatusBarVisibility();

                    // clear out disconnect timeout
                    if (disconnectTimeout) {
                        clearTimeout(disconnectTimeout);
                        disconnectTimeout = null;
                    }

                    // retry connecting if no disconnection
                    if (isDisconnecting) {
                        isDisconnecting = false;
                        logPlugin("[WS] WebSocket disconnected");
                        activeConnectPromise = null;
                    }
                    else {
                        startTime = Date.now();
                        maxWaitMs = 5000;
                        setTimeout(tryConnect, 300);
                        logPlugin("[WS] WebSocket disconnected, retrying...");
                    }
                };

                activeConnectPromise = null;
                return resolve(true);
            };

            ws.onerror = () => {
                // Ignore, wait for onclose
            };

            ws.onclose = () => {
                setTimeout(tryConnect, 300);
            };
        }

        tryConnect();
    });
    return activeConnectPromise;
}


function disconnectWebSocket() {
    if (!socket) {
        return;
    }

    logPlugin("[WS] Disconnecting from server...");

    isDisconnecting = true;
    if (disconnectTimeout) {
        clearTimeout(disconnectTimeout);
    }

    socket.close();
    // socket = null on the lambda

    // clear isDisconnecting
    disconnectTimeout = setTimeout(() => {
        isDisconnecting = false;
        disconnectTimeout = null;
        if (socket) {
            logPlugin("[WS] WARNING: socket did not close after timeout");
        }
    }, 3000);
}

function startServer(context: vscode.ExtensionContext) {
    const exePath = ensureLocalBinary(context);
    logPlugin(`[INFO] Starting server from: ${exePath} logfile at ${logFilePath}`);

    let serverProcess = spawn(
        exePath, ["--ws", "--log-file", logFilePath], {
            detached: true,
            stdio: "ignore",
            cwd: path.dirname(exePath),
            windowsHide: true,
        }
    );

    serverProcess.on("error", (err) => {
        logPlugin(`[ERROR] Failed to start server: ${err.message}`);
    });

    serverProcess.unref()
}

async function connectOrStartServer(context: vscode.ExtensionContext) {
    let didConnect = await tryConnectWebSocket(2000);
    if (!didConnect) {
        logPlugin("[WS] No server found, starting local server...");
        await stopServer();
        startServer(context);
        if (!(await tryConnectWebSocket(5000))) {
            logPlugin("[WS] ERROR: Could not connect to started local server!")
        }
    }
}

async function stopServer() {
    disconnectWebSocket();
    await cleanupOrphanProcesses();
    // TODO wait for server process to die
}

async function restartServer(context: vscode.ExtensionContext) {
    await stopServer();
    await new Promise((res) => setTimeout(res, 300)); // wait a bit
    await connectOrStartServer(context);
}

export class ExecCodeViewProvider implements vscode.WebviewViewProvider {
    public static readonly viewType = 'dzdbgport.execCodeView';
    public view?: vscode.WebviewView;
  
    constructor(private readonly _extensionUri: vscode.Uri) {}
  
    resolveWebviewView(
        webviewView: vscode.WebviewView,
        _context: vscode.WebviewViewResolveContext,
        _token: vscode.CancellationToken
    ) {
        logPlugin("[WEBVIEW] resolve");
        this.view = webviewView;
        webviewView.webview.options = {
            enableScripts: true
        };
  
        webviewView.webview.html = this.getHtml();
  
        webviewView.webview.onDidReceiveMessage(async (message) => {
            if (message.type === "exec") {
                const code = message.code;
                const module = message.module;
                if (!code || !module) {
                    return;
                }

                let port = ports.get(selectedPort);
                if (!port) {
                    showNotification("❌ Cannot execute code: Game is not connected.", 5000);
                }
                else if (sendWebSocketMessage({ tcp_port: port.tcpPort, type: "execCode", module: module, code: code })) {
                    showNotification(`🚀 Executing code (${module})...`, 5000);
                }
                else {
                    vscode.window.showErrorMessage("❌ Cannot execute code: Socket error.");
                }
            }
        });
        
        webviewView.onDidChangeVisibility(() => {
            if (webviewView.visible) {
                updateExecButtonState();
            }
        });

        updateExecButtonState();
        webviewPostMessage({
            type: "setModules",
            modules: [
                { value: "Core",    label: "1_Core" },
                { value: "GameLib", label: "2_GameLib" },
                { value: "Game",    label: "3_Game" },
                { value: "World",   label: "4_World" },
                { value: "Mission", label: "5_Mission" },
            ]
        });
    }
  
    private getHtml(): string {
        return /*html*/`
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="UTF-8">
                <style>
                    body {
                        color: var(--vscode-foreground);
                        background-color: var(--vscode-editor-background);
                        font-family: var(--vscode-editor-font-family);
                        font-size: var(--vscode-editor-font-size);
                        padding: 10px;
                    }
    
                    textarea {
                        width: 100%;
                        padding: 8px;
                        background-color: var(--vscode-input-background);
                        color: var(--vscode-input-foreground);
                        border: 1px solid var(--vscode-input-border);
                        border-radius: 4px;
                        font-family: var(--vscode-editor-font-family);
                        font-size: var(--vscode-editor-font-size);
                        box-sizing: border-box;
                        resize: vertical;
                        min-height: 2.25em;
                    }
    
                    textarea::placeholder {
                        color: var(--vscode-input-placeholderForeground);
                    }
    
                    button {
                        margin-top: 10px;
                        padding: 6px 12px;
                        background-color: var(--vscode-button-background);
                        color: var(--vscode-button-foreground);
                        border: none;
                        border-radius: 4px;
                        cursor: pointer;
                        font-family: var(--vscode-editor-font-family);
                        font-size: var(--vscode-editor-font-size);
                    }
    
                    button:hover {
                        background-color: var(--vscode-button-hoverBackground);
                    }

                    button:disabled {
                        background-color: var(--vscode-button-disabledBackground, #444);
                        color: var(--vscode-disabledForeground, #888);
                        cursor: not-allowed;
                        opacity: 0.6;
                    }

                    button:disabled:hover {
                        background-color: var(--vscode-button-disabledBackground, #444); /* no hover change */
                    }

                    #execBtnWrapper {
                        display: inline-block;
                    }
                    
                    select {
                        padding: 6px 12px;
                        background-color: var(--vscode-input-background);
                        color: var(--vscode-input-foreground);
                        border: 1px solid var(--vscode-input-border);
                        border-radius: 4px;
                        font-family: var(--vscode-editor-font-family);
                        font-size: var(--vscode-editor-font-size);
                        margin-right: 8px;
                    }

                    select:hover, select:focus {
                        outline: none;
                        border-color: var(--vscode-focusBorder);
                    }
                </style>
            </head>
            <body>
                <textarea id="code" placeholder="Enter EnScript here..."></textarea><br/>
                <span id="execBtnWrapper">
                    <select id="modulesDropdown"></select>
                    <button id="execBtn" disabled>Execute</button>
                </span>
                <script>
                    const vscode = acquireVsCodeApi();

                    const codeBox = document.getElementById("code");
                    const modulesDropdown = document.getElementById("modulesDropdown");
                    const execBtn = document.getElementById("execBtn");
                    const execBtnWrapper = document.getElementById("execBtnWrapper");

                    // Restore state
                    const prevState = vscode.getState();
                    if (prevState) {
                        if (prevState.code) {
                            codeBox.value = prevState.code;
                        }
                        if (prevState.module) {
                            modulesDropdown.value = prevState.module;
                        }
                    }

                    // Also update state on input for live saving
                    codeBox.addEventListener("input", () => {
                        vscode.setState({ code:codeBox.value, module:modulesDropdown.value });
                    });

                    function execCode() {
                        const code = codeBox.value;
                        const module = modulesDropdown.value;
                        vscode.setState({ code, module });  // save code for future sessions
                        vscode.postMessage({ type: "exec", code, module });
                    }
                    execBtn.addEventListener("click", execCode);

                    codeBox.addEventListener("keydown", (event) => {
                        if (event.key === "Enter" && event.ctrlKey) {
                            if (!execBtn.disabled) {
                                execCode();
                                event.preventDefault();
                            }
                        }
                    });

                    window.addEventListener("message", (event) => {
                        const msg = event.data;
                        if (msg.type === "executeEnabled") {
                            if (msg.enabled) {
                                execBtn.disabled = false;
                                execBtnWrapper.title = "";
                            }
                            else {
                                execBtn.disabled = true;
                                execBtnWrapper.title = "Game is not connected";
                            }
                        }
                        else if (msg.type === "focusExecInput") {
                            codeBox.focus();
                        }
                        else if (msg.type === "setModules") {
                            modulesDropdown.innerHTML = "";
                            msg.modules.forEach(module => {
                                const option = document.createElement("option");
                                option.value = module.value;
                                option.textContent = module.label;
                                modulesDropdown.appendChild(option);
                            });
                            const prevState = vscode.getState();
                            if (prevState && prevState.module) {
                                modulesDropdown.value = prevState.module;
                            }
                        }
                    });
                </script>
            </body>
        </html>
        `;
    }
}

class LoadedFileDecorationProvider implements vscode.FileDecorationProvider {
    private _onDidChangeFileDecorations = new vscode.EventEmitter<vscode.Uri | vscode.Uri[] | undefined>();
    readonly onDidChangeFileDecorations = this._onDidChangeFileDecorations.event;

    provideFileDecoration(uri: vscode.Uri): vscode.ProviderResult<vscode.FileDecoration> {
        const fsPath = uri.fsPath.toLowerCase();

        // Dynamically resolve expected fsPaths from current dataPath
        const dataPath = pluginConfig().dataPath;
        const possibleMatches = new Set<string>();

        for (const rawPath of loadedFiles.keys()) {
            const resolved = path.isAbsolute(rawPath)
                ? path.normalize(rawPath).toLowerCase()
                : path.resolve(dataPath, rawPath).toLowerCase();

            possibleMatches.add(resolved);
        }

        if (possibleMatches.has(fsPath)) {
            vscode.commands.executeCommand("setContext", "dzdbgport.isLoadedFile", true);

            return {
                badge: "Z",
                tooltip: "Loaded by DayZ",
                color: new vscode.ThemeColor("dzdbgport.loadedFileColor"),
                propagate: true,
            };
        }

        return undefined;
    }

    notifyChange() {
        this._onDidChangeFileDecorations.fire(undefined); // Refresh all
    }
}

function findLoadedFileForUri(uri: vscode.Uri): string | null {
    const input = path.normalize(uri.fsPath).toLowerCase();
    const dataPath = pluginConfig().dataPath;

    for (const rawPath of loadedFiles.keys()) {
        const cleaned = path.normalize(rawPath.replace(/\//g, path.sep));
        const full = path.isAbsolute(cleaned)
            ? cleaned
            : path.resolve(dataPath, cleaned);
        if (path.normalize(full).toLowerCase() === input) {
            return rawPath;
        }
    }

    return null;
}

async function toggleDebugPort()
{
    const config = vscode.workspace.getConfiguration("dzdbgport");
    const targetState = !config.get<boolean>("enableDebugPort", true);
    await config.update("enableDebugPort", targetState, vscode.ConfigurationTarget.Global);
    if (targetState) {
        showNotification(`🟢 DayZ Debug Port Enabled`, 5000);
    }
    else {
        showNotification(`🔴 DayZ Debug Port Disabled`, 5000);
    }
}

async function ensurePluginEnabled(): Promise<boolean> {
    if (pluginConfig().enableDebugPort) {
        return true;
    }

    const result = await vscode.window.showWarningMessage(
        "DayZ Debug Port plugin is currently disabled. Do you want to enable it?",
        "Enable", "Cancel"
    );

    // re-check if debug port is disabled
    if (result === "Enable" && !pluginConfig().enableDebugPort) {
        await toggleDebugPort();
    }

    return false;
}

async function refreshDebugPortEnablement(context: vscode.ExtensionContext)
{
    if (pluginConfig().enableDebugPort) {
        logPlugin("[CONFIG] Debug port enabled");
        vscode.commands.executeCommand("setContext", "dzdbgport.enableDebugPort", true);

        await connectOrStartServer(context);
    }
    else {
        logPlugin("[CONFIG] Debug port disabled");
        vscode.commands.executeCommand("setContext", "dzdbgport.enableDebugPort", false);

        disconnectWebSocket();
    }

    updateStatusBarItem();
    updateStatusBarVisibility();
}

async function dumpDiag(context: vscode.ExtensionContext) {
    const lines = [];
    lines.push(`# DayZ Debug Port Diagnostics`);
    lines.push(`timestamp: ${new Date().toISOString()}`);
    lines.push(`config.enableDebugPort: ${pluginConfig().enableDebugPort}`)
    lines.push(`config.dataPath: ${pluginConfig().dataPath}`);
    lines.push(`ports: ${[...ports.keys()]}`);
    lines.push(`loadedFiles.size: ${loadedFiles.size}`)
    if (loadedFiles.size > 0) {
        lines.push(`loadedFiles:`);
        for (const [file, count] of Array.from(loadedFiles.entries()).sort()) {
            lines.push(`- name: ${file} (count: ${count})`);
        }
    }

    const content = lines.join("\n");
    const doc = await vscode.workspace.openTextDocument({
        content,
        language: "plaintext"
    });
    await vscode.window.showTextDocument(doc, { preview: false });
}

export async function activate(context: vscode.ExtensionContext) {

    ensureLocalBinary

    outputChannel = vscode.window.createOutputChannel("DayZ Debug Port");
    context.subscriptions.push(outputChannel);

    gameLogChannel = vscode.window.createOutputChannel("DayZ Log");
    context.subscriptions.push(gameLogChannel);

    context.subscriptions.push(
        vscode.commands.registerCommand("dzdbgport.dumpDiag", async () => {
            await dumpDiag(context);
        }),

        vscode.commands.registerCommand("dzdbgport.toggleDebugPort", async () => {
            await toggleDebugPort();
        }),

        vscode.commands.registerCommand("dzdbgport.viewOutput", () => {
            outputChannel.show(true);
        }),

        vscode.commands.registerCommand("dzdbgport.viewGameLogs", () => {
            gameLogChannel.show(true);
        }),

        vscode.commands.registerCommand("dzdbgport.restartServer", async () => {
            // if plugin has started, no need to restart the server
            if (await ensurePluginEnabled()) {
                await restartServer(context);
            }
        }),

        vscode.commands.registerCommand("dzdbgport.focusExecInput", async () => {
            if (!pluginConfig().enableDebugPort) {
                return;
            }
            
            execCodeViewProvider.view?.show?.(true);
            execCodeViewProvider.view?.webview.postMessage({ type: "focusExecInput" });
        }),

        vscode.commands.registerCommand("dzdbgport.recompileFile", async (uri?: vscode.Uri) => {
            if (!pluginConfig().enableDebugPort) {
                return ;
            }

            if (!uri && vscode.window.activeTextEditor) {
                uri = vscode.window.activeTextEditor.document.uri;
            }
        
            if (!uri) {
                return;
            }

            const loadedFile = findLoadedFileForUri(uri);
            if (!loadedFile) {
                logPlugin(`Cannot recompile file ${uri.fsPath} because it isn't loaded by any game instance`);
                showNotification(`❌ Cannot recompile "${path.basename(uri.fsPath)}": Not loaded by any game instance`, 5000);
                return;
            }
            
            if (sendWebSocketMessage({ type: "recompile", filename: loadedFile })) {
                logPlugin(`Recompiling ${uri.fsPath}`);
                showNotification(`🛠️ Recompiling "${path.basename(uri.fsPath)}"...`, 5000);
            }
            else {
                logPlugin(`Could not recompile ${uri.fsPath}, socket error`);
                vscode.window.showErrorMessage(`❌ Cannot recompile: Socket error.`);
            }
        }),

        vscode.commands.registerCommand("dzdbgport.selectTargetPort", async () => {
            await pickTargetPort();
        }),
    );

    execCodeViewProvider = new ExecCodeViewProvider(context.extensionUri);
    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider(
            ExecCodeViewProvider.viewType,
            execCodeViewProvider
        )
    );

    decorationProvider = new LoadedFileDecorationProvider();
    context.subscriptions.push(
        vscode.window.registerFileDecorationProvider(decorationProvider)
    );

    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right);
    context.subscriptions.push(statusBarItem);
    updateStatusBarVisibility();
    vscode.window.onDidChangeActiveTextEditor(updateStatusBarVisibility, null, context.subscriptions);

    // Watch for config changes (like dataPath)
    vscode.workspace.onDidChangeConfiguration(async (event) =>{
        if (event.affectsConfiguration("dzdbgport.dataPath")) {
            decorationProvider.notifyChange(); // Refresh all loaded file markings
        }

        if (event.affectsConfiguration("dzdbgport.enableDebugPort")) {
            await refreshDebugPortEnablement(context);
        }
    });
    await refreshDebugPortEnablement(context);

    // server is started from `refreshDebugPortEnablement()`
}

export async function deactivate(): Promise<void> {
    disconnectWebSocket();
}