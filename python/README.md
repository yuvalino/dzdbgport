# DayZ Debug Port (Python)

DayZ Debug Port is an unofficial project for DayZ modders to enable debugging outside the Workbench app that ships with DayZ tools.

## 🔧 Initial setup

To have the game connect to the DayZ Debug Port, you'll need to run the **DayZDiag_x64.exe** executable instead of the vanilla **DayZ_x64.exe** binary. Once the game runs, it will auto-connect to the extension.

![dayzdiag](https://raw.githubusercontent.com/yuvalino/dzdbgport/refs/heads/main/resources/screen-dayzdiag.jpg)

### Setup **Recompile on Host (Ctrl+F7)**

For **Recompile on Host (Ctrl+F7)** to work, you'll need to run **DayZDiag_x64.exe** with `-filePatching` flag and setup shortcuts from the game's installation folder to the projects to enable filePatching on as explained in [DayZ: Modding Basics - Preparing FilePatching](https://community.bistudio.com/wiki/DayZ:Modding_Basics?useskin=vector#Preparing_FilePatching).

Here's an example command to create a shortcut:

`mklink /J "DayZInstallationFolder\FirstMod" "P:\FirstMod"`

**NOTE:** Recompile only reloads the code! If your recompiled code doesn't run make sure it isn't something that runs once on game startup / mission startup / player connection.

## 📟 Python Package & Debug Console

The foundation for this extension is the Python package that can connect to the game and talk to it in the right protocol.

This package is bundled as an exe with the extension and talks to it using a websocket. The package also has a debug console that provides lower-level access to the functionality exposed via the VSCode extension.

![console](https://raw.githubusercontent.com/yuvalino/dzdbgport/refs/heads/main/resources/screen-console.jpg)