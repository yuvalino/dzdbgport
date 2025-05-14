# DayZ Debug Port

DayZ Debug Port is an unofficial project for DayZ modders to enable debugging outside the Workbench app that ships with DayZ tools.

## 🔧 Initial setup

To have the game connect to the DayZ Debug Port, you'll need to run the **DayZDiag_x64.exe** executable instead of the vanilla **DayZ_x64.exe** binary. Once the game runs, it will auto-connect to the extension.

![dayzdiag](https://raw.githubusercontent.com/yuvalino/dzdbgport/refs/heads/main/resources/screen-dayzdiag.jpg)

### Setup **Recompile on Host (Ctrl+F7)**

For **Recompile on Host (Ctrl+F7)** to work, you'll need to run **DayZDiag_x64.exe** with `-filePatching` flag and setup shortcuts from the game's installation folder to the projects to enable filePatching on as explained in [DayZ: Modding Basics - Preparing FilePatching](https://community.bistudio.com/wiki/DayZ:Modding_Basics?useskin=vector#Preparing_FilePatching).

Here's an example command to create a shortcut:

`mklink /J "DayZInstallationFolder\FirstMod" "P:\FirstMod"`

**NOTE:** Recompile only reloads the code! If your recompiled code doesn't run make sure it isn't something that runs once on game startup / mission startup / player connection.

## 🧩 VSCode Extension

1. **Active Game Connection:** Maintains a connection to the game with realtime notifications for game connections, game exit and game crashes.

![statusbar](https://raw.githubusercontent.com/yuvalino/dzdbgport/refs/heads/main/resources/screen-statusbar.jpg)

Also an output channel for the debug port logs themselves.

2. **Live Logs:** Output channel for logs from the connected game, streamed live.

![logs](https://raw.githubusercontent.com/yuvalino/dzdbgport/refs/heads/main/resources/screen-logs.jpg)

3. **Code Exec**: Convenient window with script input to execute on the connected game.

4. **Recompile on Host**: Same old `Ctrl+F7` shortcut to recompile files loaded by the game. Loaded files are colored and makred with a **Z** badge beside their filename in the explorer and editor. Right click in the explorer also allows recompiling the file.

![sidebar](https://raw.githubusercontent.com/yuvalino/dzdbgport/refs/heads/main/resources/screen-sidebar.jpg)

5. **And other commands**: Plugin is as versatile as possible.

![cmdpallette](https://raw.githubusercontent.com/yuvalino/dzdbgport/refs/heads/main/resources/screen-cmdpallette.jpg)