import * as vscode from "vscode";
import { spawn, ChildProcessWithoutNullStreams } from "child_process";
import * as path from "path";
import WebSocket from "ws";

let serverProcess: ChildProcessWithoutNullStreams | null = null;
let socket: WebSocket | null = null;
let outputChannel: vscode.OutputChannel;

function logPlugin(msg: string, end: string = "\n") {
    outputChannel.append(`[plugin ] ${msg}${end}`)
}

function logPort(msg: string, end: string = "\n") {
    outputChannel.append(`[dbgport] ${msg}${end}`)
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

function onWebSocketMessage(msg: any) {
    if (msg.type === "connect") {
        logPlugin(`[WS] Game connected (pid: ${msg.pid})`);
        vscode.window.showInformationMessage(`🟢 DayZ Game Connected (PID: ${msg.pid})`);
    } else if (msg.type === "disconnect") {
        logPlugin(`[WS] Game disconnected (pid: ${msg.pid}, reason: ${msg.reason})`);
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

            ws.onerror = (err) => {
                logPlugin("[WS] WebSocket error.");
                console.error(err);
            };
        
            ws.onclose = () => {
                logPlugin("[WS] WebSocket disconnected.");
                socket = null;
            };
        };

        ws.onmessage = (event) => {
            const raw = event.data;
            const text = typeof raw === "string" ? raw : raw.toString();
            const msg = JSON.parse(text);

            onWebSocketMessage(msg);
        };

        ws.onerror = () => {
            // do nothing here, retry silently
        };

        ws.onclose = () => {
            if (!connected) {
                setTimeout(tryConnect, retryMs); // retry
            } else {
                logPlugin("[WS] WebSocket disconnected.");
                socket = null;
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

export async function activate(context: vscode.ExtensionContext) {
    outputChannel = vscode.window.createOutputChannel("DayZ Debug Port");
    context.subscriptions.push(outputChannel);

    await cleanupOrphanProcesses();
    startServer(context);

    context.subscriptions.push(
        vscode.commands.registerCommand("dzdbgport.viewLogs", () => {
            outputChannel.show(true);
        }),

        vscode.commands.registerCommand("dzdbgport.restartServer", () => {
            restartServer(context);
        }),
    );
}

export async function deactivate(): Promise<void> {
    await stopServer();
}