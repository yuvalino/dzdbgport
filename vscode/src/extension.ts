import * as vscode from 'vscode';

export function activate(context: vscode.ExtensionContext) {
    const outputChannel = vscode.window.createOutputChannel('DayZ Logs');

    const disposable = vscode.commands.registerCommand('dayzDebugger.showLog', () => {
        outputChannel.show();
        outputChannel.appendLine(`[INFO] DayZ Debugger Started at ${new Date().toISOString()}`);
    });

    context.subscriptions.push(disposable);
}

export function deactivate() {}