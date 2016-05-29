SET iddaa=%~dp0
copy "%iddaa%idapython\cgchelper.py" "C:\Program Files (x86)\IDA 6.8\plugins"
copy "%iddaa%idapython\rpcserver.py" "C:\Program Files (x86)\IDA 6.8\plugins"
xcopy "%iddaa%idapython\iddaa" "C:\Program Files (x86)\IDA 6.8\plugins\iddaa" /S /Y /I /D
pause
