Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
batPath = fso.GetParentFolderName(WScript.ScriptFullName) & "\start-hidden.bat"
If fso.FileExists(batPath) Then
  WshShell.Run """" & batPath & """, 0, False
Else
  WScript.Echo "Launcher not found: " & batPath
End If
