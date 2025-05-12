# DayZ Debug Port

[![image](https://img.shields.io/pypi/v/dzdbgport.svg?logo=pypi&logoColor=white)](https://pypi.python.org/pypi/dzdbgport)
[![Discord](https://img.shields.io/badge/Submit%20Feedback-7289DA?logo=discord&logoColor=white&label=&style=flat)](https://discord.gg/BVSeTgAgJw)

DayZ Debug Port is an unofficial project for DayZ modders to enable debugging outside the Workbench app that ships with DayZ tools.

## 🧩 VSCode Extension

1. **Active Game Connection:** Maintains a connection to the game with realtime notifications for game connections, game exit and game crashes.

![statusbar](resources/screen-statusbar.jpg)

Also an output channel for the debug port logs themselves.

2. **Live Logs:** Output channel for logs from the connected game, streamed live.

![logs](resources/screen-logs.jpg)

3. **Code Exec**: Convenient window with script input to execute on the connected game.

4. **Recompile on Host**: Same old `Ctrl+F7` shortcut to recompile files loaded by the game. Loaded files are colored and makred with a **Z** badge beside their filename in the explorer and editor. Right click in the explorer also allows recompiling the file.

![sidebar](resources/screen-sidebar.jpg)

5. **And other commands**: Plugin is as versatile as possible.

![cmdpallette](resources/screen-cmdpallette.jpg)

## 📟 Python Package & Debug Console

The foundation for this extension is the Python package that can connect to the game and talk to it in the right protocol.

This package is bundled as an exe with the extension and talks to it using a websocket. The package also has a debug console that provides lower-level access to the functionality exposed via the VSCode extension.

![console](resources/screen-console.jpg)
