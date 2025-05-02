import * as vscode from "vscode";
import { spawn, ChildProcessWithoutNullStreams } from "child_process";
import * as path from "path";

let serverProcess: ChildProcessWithoutNullStreams | null = null;
let outputChannel: vscode.OutputChannel;

function log_plugin(msg: string, end: string = "\n") {
    outputChannel.append(`[plugin ] ${msg}${end}`)
}

function log_port(msg: string, end: string = "\n") {
    outputChannel.append(`[dbgport] ${msg}${end}`)
}

function startServer(context: vscode.ExtensionContext) {
    if (serverProcess) {
        log_plugin("[INFO] Server already running.");
        return;
    }

    const exePath = path.join(context.extensionPath, "bin", "dzdbgport.exe");
    log_plugin(`[INFO] Starting server from: ${exePath}`);

    serverProcess = spawn(exePath, ["--ws"], { cwd: path.dirname(exePath) });

    serverProcess.stdout.on("data", (data) => {
        data.toString().split(/\r?\n/).forEach((line: string) => {
            if (line.trim() !== "") {
                log_port(line);
            }
        });
    });
    
    serverProcess.stderr.on("data", (data) => {
        data.toString().split(/\r?\n/).forEach((line: string) => {
            if (line.trim() !== "") {
                log_port(`[stderr] ${line}`);
            }
        });
    });

    serverProcess.on("close", (code) => {
        log_plugin(`[INFO] Server exited with code ${code}`);
        serverProcess = null;
    });

    serverProcess.on("error", (err) => {
        log_plugin(`[ERROR] Failed to start server: ${err.message}`);
        serverProcess = null;
    });
}

async function stopServer(): Promise<void> {
    return new Promise((resolve) => {
        if (!serverProcess || serverProcess.killed) return;

        const pid = serverProcess.pid;
        log_plugin(`[INFO] Force-killing server process with PID ${pid}`);

        const killer = spawn("taskkill", ["/PID", String(pid), "/T", "/F"]);

        killer.on("exit", () => {
            log_plugin(`[INFO] taskkill complete.`);
            serverProcess = null;
            resolve();
        });

        killer.on("error", (err) => {
            log_plugin(`[ERROR] Failed to run taskkill: ${err.message}`);
            serverProcess = null;
            resolve();
        });
    });
}

async function restartServer(context: vscode.ExtensionContext) {
    await stopServer();
    await new Promise((res) => setTimeout(res, 300)); // wait a bit
    startServer(context);
}

export function activate(context: vscode.ExtensionContext) {
    outputChannel = vscode.window.createOutputChannel("DayZ Debug Port");
    context.subscriptions.push(outputChannel);

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