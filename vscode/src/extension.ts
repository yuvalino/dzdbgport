import * as vscode from "vscode";
import { spawn, ChildProcessWithoutNullStreams } from "child_process";
import * as path from "path";
import WebSocket from "ws";

let serverProcess: ChildProcessWithoutNullStreams | null = null;
let socket: WebSocket | null = null;
let outputChannel: vscode.OutputChannel;
let gameConnected = false;
let execCodeViewProvider: ExecCodeViewProvider;
let decorationProvider: LoadedFileDecorationProvider;
const loadedFiles = new Set<string>();

function logPlugin(msg: string, end: string = "\n") {
    outputChannel.append(`[plugin ] ${msg}${end}`)
}

function logPort(msg: string, end: string = "\n") {
    outputChannel.append(`[dbgport] ${msg}${end}`)
}

function clearLoadedFiles(): void {
    loadedFiles.clear();
    decorationProvider.notifyChange();
    logPlugin("[WS] Cleared loaded file list");
}

interface PluginConfig {
    dataPath: string;
}

function pluginConfig(): PluginConfig {
    const config = vscode.workspace.getConfiguration("dzdbgport");
    return {
        dataPath: config.get<string>("dataPath", "P:\\")!,
    };
}

function webviewPostMessage(message: any) {
    if (execCodeViewProvider && execCodeViewProvider.view) {
        execCodeViewProvider.view.webview.postMessage(message);
    }
}

function updateExecButtonState() {
    const enabled = (socket && socket.readyState === WebSocket.OPEN && gameConnected);
    webviewPostMessage({ type: "executeEnabled", enabled: enabled });
}

async function cleanupOrphanProcesses(): Promise<void> {
    return new Promise((resolve) => {
        const killer = spawn("taskkill", ["/IM", "dzdbgport.exe", "/F", "/T"]);
        killer.on("exit", () => {
            logPlugin(`[INFO] taskkill complete.`);
            serverProcess = null;
            resolve();
        });

        killer.on("error", (err) => {
            logPlugin(`[ERROR] Failed to run taskkill: ${err.message}`);
            serverProcess = null;
            resolve();
        });
    });
}

function sendWebSocketMessage(msg: any): boolean {
    if (socket && socket.readyState === socket.OPEN) {
        socket.send(JSON.stringify(msg));
        return true;
    }

    return false;
}

function onWebSocketMessage(msg: any) {
    if (msg.type === "connect") {
        logPlugin(`[WS] Game connected (pid: ${msg.pid})`);

        gameConnected = true;
        updateExecButtonState();

        vscode.window.showInformationMessage(`🟢 DayZ Game Connected (PID: ${msg.pid})`);
    } else if (msg.type === "disconnect") {
        logPlugin(`[WS] Game disconnected (pid: ${msg.pid}, reason: ${msg.reason})`);

        gameConnected = false;
        updateExecButtonState();
        clearLoadedFiles();

        if (msg.reason === "exit") {
            vscode.window.showInformationMessage(`🟡 DayZ Game Disconnected (PID: ${msg.pid})`);
        }
        else if (msg.reason === "crash") {
            vscode.window.showWarningMessage(`🔴 DayZ Game Crashed (PID: ${msg.pid})`);
        }
        else {
            vscode.window.showWarningMessage(`🔴 DayZ Game Unknown Exit Reason (PID: ${msg.pid}, Reason: ${msg.reason})`);
        }
    }
    else if (msg.type === "block_load") {
        if (msg.filenames.length == 1 && msg.filenames[0] === "execCode") {
            logPlugin(`[WS] Code executed successfully (id 0x${msg.block_id.toString(16)})`);
            return;
        }

        logPlugin(`[WS] Block loaded (id 0x${msg.block_id.toString(16)}, ${msg.filenames.length} files)`)
        for (const file of msg.filenames) {
            loadedFiles.add(file);
        }
        decorationProvider.notifyChange();
    }
    else if (msg.type === "block_unload") {
        if (msg.filenames.length == 1 && msg.filenames[0] === "execCode") {
            return;
        }

        logPlugin(`[WS] Block unloaded (id 0x${msg.block_id.toString(16)}, ${msg.filenames.length} files)`)
        for (const file of msg.filenames) {
            loadedFiles.delete(file);
        }
        decorationProvider.notifyChange();
    }
    else {
        logPlugin(`[WS] [WARN] Unknown message type ${msg.type}`)
    }
}

function connectWebSocket(retryMs = 500, maxWaitMs = 5000) {
    const wsUrl = "ws://localhost:28051";
    let startTime = Date.now();
    let connected = false;
    let errorShown = false;

    logPlugin("[WS] Connecting to server...");

    function tryConnect() {
        if (connected || Date.now() - startTime > maxWaitMs) {
            if (!connected && !errorShown) {
                logPlugin("[WS] Failed to connect to server after retrying.");
                vscode.window.showErrorMessage("❌ Could not connect to DayZ debug server.");
                errorShown = true;
            }
            return;
        }

        const ws = new WebSocket(wsUrl);

        ws.onopen = () => {
            logPlugin("[WS] Connected to server.");
            connected = true;
            socket = ws;
            updateExecButtonState();
            clearLoadedFiles();

            ws.onerror = (err) => {
                logPlugin("[WS] WebSocket error.");
                console.error(err);
            };
        
            ws.onclose = () => {
                logPlugin("[WS] WebSocket disconnected.");
                socket = null;
                gameConnected = false;
                updateExecButtonState();
                clearLoadedFiles();
            };
        };

        ws.onmessage = (event) => {
            const raw = event.data;
            const text = typeof raw === "string" ? raw : raw.toString();
            const msg = JSON.parse(text);

            onWebSocketMessage(msg);
        };

        ws.onerror = () => {
            // do nothing here, retry silently (onclose called soon after)
        };

        ws.onclose = () => {
            if (!connected) {
                setTimeout(tryConnect, retryMs); // retry
            } else {
                logPlugin("[WS] WebSocket disconnected.");
                socket = null;
                gameConnected = false;
                updateExecButtonState();
                clearLoadedFiles();
            }
        };
    }

    tryConnect();
}


function disconnectWebSocket() {
    if (socket) {
        logPlugin("[WS] Disconnecting from server...");
        socket.close();
        socket = null;
    }
}

function startServer(context: vscode.ExtensionContext) {
    if (serverProcess) {
        logPlugin("[INFO] Server already running.");
        return;
    }

    const exePath = path.join(context.extensionPath, "bin", "dzdbgport.exe");
    logPlugin(`[INFO] Starting server from: ${exePath}`);

    serverProcess = spawn(exePath, ["--ws"], { cwd: path.dirname(exePath) });

    serverProcess.stdout.on("data", (data) => {
        data.toString().split(/\r?\n/).forEach((line: string) => {
            if (line.trim() !== "") {
                logPort(line);
            }
        });
    });
    
    serverProcess.stderr.on("data", (data) => {
        data.toString().split(/\r?\n/).forEach((line: string) => {
            if (line.trim() !== "") {
                logPort(`[stderr] ${line}`);
            }
        });
    });

    serverProcess.on("close", (code) => {
        logPlugin(`[INFO] Server exited with code ${code}`);
        serverProcess = null;
    });

    serverProcess.on("error", (err) => {
        logPlugin(`[ERROR] Failed to start server: ${err.message}`);
        serverProcess = null;
    });

    connectWebSocket()
}

async function stopServer() {
    disconnectWebSocket();

    if (!serverProcess || serverProcess.killed) return;

    const pid = serverProcess.pid;
    logPlugin(`[INFO] Force-killing server process with PID ${pid}`);

    await cleanupOrphanProcesses();

    // TODO wait for server process to die
}

async function restartServer(context: vscode.ExtensionContext) {
    await stopServer();
    await new Promise((res) => setTimeout(res, 300)); // wait a bit
    startServer(context);
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
        this.view = webviewView;
        webviewView.webview.options = {
            enableScripts: true
        };
  
        webviewView.webview.html = this.getHtml();
  
        webviewView.webview.onDidReceiveMessage(async (message) => {
            if (message.type === "exec") {
                const code = message.code;
                if (!code) {
                    return;
                }

                if (sendWebSocketMessage({ type: "execCode", module: "World", code: code })) {
                    vscode.window.showInformationMessage(`🚀 Executing code...`);
                }
                else {
                    vscode.window.showErrorMessage("❌ Cannot execute code: Game is not connected.");
                }
            }
        });
        
        webviewView.onDidChangeVisibility(() => {
            if (webviewView.visible) {
                updateExecButtonState();
            }
        });

        vscode.commands.registerCommand("dzdbgport.execCodeView.focus", () => {
            webviewView.show?.(true);
            webviewView.webview.postMessage({ type: "focusExecInput" });
        });

        updateExecButtonState();
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
                </style>
            </head>
            <body>
                <textarea id="code" placeholder="Enter EnScript here..."></textarea><br/>
                <span id="execBtnWrapper">
                    <button id="execBtn" disabled>Execute</button>
                </span>
                <script>
                    const vscode = acquireVsCodeApi();

                    const codeBox = document.getElementById("code");
                    const execBtn = document.getElementById("execBtn");
                    const execBtnWrapper = document.getElementById("execBtnWrapper");

                    // Restore state
                    const prevState = vscode.getState();
                    if (prevState && prevState.code) {
                        codeBox.value = prevState.code;
                    }

                    // Also update state on input for live saving
                    codeBox.addEventListener("input", () => {
                        vscode.setState({ code:codeBox.value });
                    });

                    function execCode() {
                        const code = codeBox.value;
                        vscode.setState({ code });  // Save code for future sessions
                        vscode.postMessage({ type: "exec", code });
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

        for (const rawPath of loadedFiles) {
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

    for (const rawPath of loadedFiles) {
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

export async function activate(context: vscode.ExtensionContext) {
    outputChannel = vscode.window.createOutputChannel("DayZ Debug Port");
    context.subscriptions.push(outputChannel);

    context.subscriptions.push(
        vscode.commands.registerCommand("dzdbgport.viewLogs", () => {
            outputChannel.show(true);
        }),

        vscode.commands.registerCommand("dzdbgport.restartServer", () => {
            restartServer(context);
        }),

        vscode.commands.registerCommand("dzdbgport.focusExecInput", () => {
            vscode.commands.executeCommand('dzdbgport.execCodeView.focus');
        }),

        vscode.commands.registerCommand("dzdbgport.recompileFile", async (uri?: vscode.Uri) => {
            if (!uri && vscode.window.activeTextEditor) {
                uri = vscode.window.activeTextEditor.document.uri;
            }
        
            if (!uri) {
                return;
            }

            const loadedFile = findLoadedFileForUri(uri);
            if (!loadedFile) {
                logPlugin(`Cannot recompile file ${uri.fsPath} because it isn't loaded by the game`);
            }
            
            if (sendWebSocketMessage({ type: "recompile", filename: loadedFile })) {
                logPlugin(`Recompiling ${uri.fsPath}`);
                vscode.window.showInformationMessage(`🛠️ Recompiling "${path.basename(uri.fsPath)}"...`);
            }
            else {
                logPlugin(`Could not recompile ${uri.fsPath}, game not connected`);
                vscode.window.showErrorMessage(`❌ Cannot recompile "${path.basename(uri.fsPath)}}": Game is not connected.`);
            }
        })
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

    // Watch for config changes (like dataPath)
    vscode.workspace.onDidChangeConfiguration((event) => {
        if (event.affectsConfiguration("dzdbgport.dataPath")) {
            decorationProvider.notifyChange(); // Refresh all loaded file markings
        }
    });

    await cleanupOrphanProcesses();
    startServer(context);
}

export async function deactivate(): Promise<void> {
    await stopServer();
}