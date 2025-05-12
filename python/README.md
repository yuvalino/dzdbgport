# DayZ Debug Port (Python)

DayZ Debug Port is an unofficial project for DayZ modders to enable debugging outside the Workbench app that ships with DayZ tools.

## 📟 Python Package & Debug Console

The foundation for this extension is the Python package that can connect to the game and talk to it in the right protocol.

This package is bundled as an exe with the extension and talks to it using a websocket. The package also has a debug console that provides lower-level access to the functionality exposed via the VSCode extension.

![console](https://raw.githubusercontent.com/yuvalino/dzdbgport/refs/heads/main/resources/screen-console.jpg)