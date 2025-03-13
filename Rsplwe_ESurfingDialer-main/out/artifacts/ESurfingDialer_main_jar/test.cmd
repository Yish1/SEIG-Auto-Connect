@echo off
chcp 65001
title ESurfingDialer-One-Click-Windows-1.8.1
setlocal enabledelayedexpansion
set "ver=2025-2-20"
set "config_file=%~dp0config.txt"
set "JAVA_HOME=.\jre"

if not exist "%config_file%" (
  :input_account
  set /p "account=请输入校园网账号: "
  if "!account!"=="" (
    echo 账号不能为空，请重新输入。
    goto input_account
  )
  
  :input_pwd
  set /p "pwd=请输入校园网密码: "
  if "!pwd!"=="" (
    echo 密码不能为空，请重新输入。
    goto input_pwd
  )

  :input_userIp
  set /p "userIp=请输入目标ip: "
  if "!userIp!"=="" (
    echo ip不能为空，请重新输入。
    goto input_userIp
  )

  :input_acIp
  set /p "acIp=请输入服务器的目标ip: "
  if "!acIp!"=="" (
    echo ip不能为空，请重新输入。
    goto input_acIp
  )

) else (
  for /F "tokens=1,2 delims==" %%a in (%config_file%) do (
    if "%%a"=="account" set "account=%%b"
    if "%%a"=="pwd" set "pwd=%%b"
    if "%%a"=="userIp" set "userIp=%%b"
    if "%%a"=="acIp" set "acIp=%%b"
  )
)

(
  echo account=%account%
  echo pwd=%pwd%
  echo userIp=%userIp%
  echo acIp=%acIp%
) > "%config_file%"

echo 账号为%account% 密码为%pwd% 目标登录ip为%userIp% 登录服务器为%acIp%

set "DIRNAME=%~dp0"
if "%DIRNAME%"=="" set "DIRNAME=."
set "APP_HOME=%DIRNAME%.."

for %%i in ("%APP_HOME%") do set "APP_HOME=%%~fi"

set "JAVA_EXE=%JAVA_HOME%\bin\java.exe"

if not exist "%JAVA_EXE%" (
  echo Java 不存在，检查 JAVA_HOME 设置。
  exit /b
)

if not exist "client.jar" (
  echo client.jar 文件未找到！
  exit /b
)

"%JAVA_EXE%" -jar client.jar -u %account% -p %pwd% -t %userIp% -a %acIp%

endlocal
