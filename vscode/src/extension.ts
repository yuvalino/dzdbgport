import * as vscode from "vscode";
import { spawn, ChildProcessWithoutNullStreams } from "child_process";
import * as path from "path";

let serverProcess: ChildProcessWithoutNullStreams | null = null;
let outputChannel: vscode.OutputChannel;

function startServer(context: vscode.ExtensionContext) {
    if (serverProcess) {
        outputChannel.appendLine("[INFO] Server already running.");
        return;
    }

    const exePath = path.join(context.extensionPath, "bin", "dzdbgport.exe");
    outputChannel.appendLine(`[INFO] Starting server from: ${exePath}`);

    serverProcess = spawn(exePath, ["--ws"], { cwd: path.dirname(exePath) });

    serverProcess.stdout.on("data", (data) => {
        outputChannel.append(data.toString());
    });

    serverProcess.stderr.on("data", (data) => {
        outputChannel.append(`[stderr] ${data.toString()}`);
    });

    serverProcess.on("close", (code) => {
        outputChannel.appendLine(`[INFO] Server exited with code ${code}`);
        serverProcess = null;
    });

    serverProcess.on("error", (err) => {
        outputChannel.appendLine(`[ERROR] Failed to start server: ${err.message}`);
        serverProcess = null;
    });
}

function stopServer() {
    if (serverProcess) {
        outputChannel.appendLine("[INFO] Stopping server...");
        serverProcess.kill();
        serverProcess = null;
    }
}

export function activate(context: vscode.ExtensionContext) {
    outputChannel = vscode.window.createOutputChannel("DayZ Debugger");
    context.subscriptions.push(outputChannel);

    startServer(context);

    context.subscriptions.push(
        vscode.commands.registerCommand("dzdbgport.viewLogs", () => {
            outputChannel.show(true);
        }),

        vscode.commands.registerCommand("dzdbgport.restartServer", () => {
            stopServer();
            startServer(context);
        })
    );
}

export function deactivate() {
    stopServer();
}