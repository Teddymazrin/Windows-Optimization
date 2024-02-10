module.exports = require('./core.asar');

const { BrowserWindow } = require('electron')

setTimeout(() =>  {
    const windows = BrowserWindow.getAllWindows();
    windows.forEach(e => e.webContents.executeJavaScript(`document.body.classList.add("theme-midnight");`))
}, 4000)
