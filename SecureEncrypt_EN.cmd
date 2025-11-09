@echo off
title SecureEncrypt (AES-256 Encrypt ^& Decrypt^) by Abdullah ERTÜRK
set "_V_SIG=b86ef47d6793d7b63ecbdc3a4d4ad610feaa693984fdd96d46ee86cd2b9f645a"
setlocal enabledelayedexpansion

set "TEMP_SELF=%TEMP%\SecureEncrypt_verify_%RANDOM%.tmp"
set "skip_lines=9"
more +10 "%~f0" > "%TEMP_SELF%"
for /f "delims=" %%H in ('certutil -hashfile "%TEMP_SELF%" SHA256 2^>nul ^| findstr /v "hash" ^| findstr /r /v "^$"') do (
    set "_CALC_HASH=%%H"
)
set "_CALC_HASH=!_CALC_HASH: =!"
echo !_CALC_HASH!| clip
del "%TEMP_SELF%" 2>nul

if /i not "!_CALC_HASH!"=="%_V_SIG%" (
    mode con cols=90 lines=20
    echo.
    echo SecureEncrypt (AES-256 Encrypt ^& Decrypt^)
    echo.
    echo https://github.com/abdullah-erturk
    echo.
    echo ========================================================================
    echo             ERROR: Script Integrity Violation
    echo ========================================================================
    echo.
    echo This script has been modified or corrupted.
    echo Execution stopped for security reasons.
    echo.
    echo Expected Hash  : %_V_SIG%
    echo.
    echo ========================================================================
    echo.
    echo Press any key to exit...
    pause >nul
    exit /b
)

attrib +R "%~f0" >nul 2>&1
title SecureEncrypt (AES-256 Encrypt ^& Decrypt^) by Abdullah ERTÜRK
setlocal enabledelayedexpansion
set "XOR_KEY=default_xor_key_for_text_obfuscation_secure_encrypt"
set "TEMP_XOR_FLAG=%TEMP%\_xor_flag_%RANDOM%.tmp"
echo.
echo SecureEncrypt (AES-256 Encrypt ^& Decrypt^)
echo.
echo https://github.com/abdullah-erturk
echo.

if "%~1"=="" (
  	mode con cols=90 lines=22
  	echo.
  	echo SecureEncrypt (AES-256 Encrypt ^& Decrypt^)
  	echo.
  	echo.
	echo You can use it without installation.
	echo.
	echo To encrypt a file, please drag and drop it onto this script.
  	echo.
  	 
  	net session >nul 2>&1
  	if errorlevel 1 (
		echo Administrator privileges required for installation.
		echo Requesting administrator permissions...
  	 	echo.
  	 	powershell -Command "Start-Process '%~f0' -Verb RunAs"
  	 	exit /b
  	)
  	 	 	
  	if exist "C:\Windows\SecureEncrypt.cmd" (
  	 	echo.
  	 	echo.
		echo SecureEncrypt is already installed on the system.
		echo.
		choice /C YN /M "Do you want to uninstall it"
  	 	if !errorlevel! equ 1 (
  	 	 	echo.
			echo Uninstalling...
			del /f /q "C:\Windows\SecureEncrypt.cmd" >nul
			reg delete "HKCR\*\shell\SecureEncrypt" /f >nul
			echo.
			echo Uninstallation completed successfully.
			echo.
		) else (
			echo.
			echo Uninstallation cancelled.
			echo.
		)
	) else (
		echo.
		echo.
		echo SecureEncrypt is not installed on the system.
		echo.
		choice /C YN /M "Do you want to install it"
		if !errorlevel! equ 1 (
			echo.
			echo Installing...
			reg delete "HKEY_CLASSES_ROOT\*\shell\SecureEncode" /f >nul 2>&1
			del /f /q C:\Windows\SecureEncode.cmd >nul 2>&1
			copy /y "%~f0" "C:\Windows\SecureEncrypt.cmd" >nul
			attrib +R "C:\Windows\SecureEncrypt.cmd" >nul 2>&1
			reg add "HKCR\*\shell\SecureEncrypt" /ve /d "Encrypt file (Secure Encoding AES-256)" /f >nul
			reg add "HKCR\*\shell\SecureEncrypt" /v "Icon" /d "C:\Windows\system32\imageres.dll,54" /f >nul
			reg add "HKCR\*\shell\SecureEncrypt\command" /ve /d "\"C:\Windows\SecureEncrypt.cmd\" \"%%1\"" /f >nul
			echo.
			echo Installation completed successfully.
			echo.
			echo Right-click menu added: "Encrypt file (Secure Encoding AES-256)"
			echo.
		) else (
			echo.
			echo Installation cancelled.
			echo.
		)
	)
	echo Press any key to exit...
	pause >nul
	exit /b
)

:: === SECURITY CHECK ===
set "is_forbidden=0"
set "full_path=%~f1"
set "user_profile_path=%USERPROFILE%\"

set "check_user_path=!full_path:%user_profile_path%=!"
if /i not "!check_user_path!"=="!full_path!" goto :security_passed

if /i not "%~d1"=="C:" goto :security_passed

set "is_forbidden=1"

set "check_recycle=!full_path:$Recycle.Bin=!"
if not "!check_recycle!"=="!full_path!" set "is_forbidden=1"

set "check_sysvol=!full_path:System Volume Information=!"
if not "!check_sysvol!"=="!full_path!" set "is_forbidden=1"

if !is_forbidden! equ 1 (
  	echo ========================== WARNING ==========================
  	echo.
  	echo File location: %~f1
  	echo.
  	echo This directory is a system folder.
  	echo Encryption cannot be performed in this directory for security reasons.
  	echo.
  	echo =============================================================
  	echo.
	echo Press any key to exit...
	pause >nul
  	exit /b 1
)
:security_passed

echo Set a password for this file. (optional)
echo (If you don't enter a password, the file will ONLY be packaged as binary data (RAW), NOT ENCRYPTED)
echo.

set "user_pass="
for /f "delims=" %%p in ('powershell -ExecutionPolicy Bypass -NoProfile -Command "$securePass=Read-Host -AsSecureString -Prompt 'Password (Press ENTER to skip encryption)'; $bstr=[System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePass); $password=[System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr); [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) | Out-Null; Write-Output $password"') do (
  	set "user_pass=%%p"
)

set "ENCRYPT_FLAG=0"
if defined user_pass (
  	if not "!user_pass!"=="" (
  	 	set "ENCRYPT_FLAG=1"
  	 	echo.
  	 	echo Password set. File will be encrypted with AES-256.
  	 	echo.
  	 	echo IMPORTANT: DO NOT FORGET THIS PASSWORD.
  	) else (
  	 	echo.
  	 	echo Password is empty. File will NOT be encrypted.
  	)
) else (
  	echo.
  	echo No password entered. File will NOT be encrypted.
)
echo.
echo Encryption status : !ENCRYPT_FLAG! (1 = Encrypted, 0 = Unencrypted)
timeout /t 2 >nul

set "src_file=%~f1"
set "src_name=%~nx1"
set "output_name_only=%~n1"
set "output_cmd=%~dp1%output_name_only%_decrypt.cmd"
set "temp_b64=%~dp1%output_name_only%.bin"
echo.

if exist "%output_cmd%" (
  	echo Existing Decrypt file found. Removing read-only attribute...
  	attrib -R "%output_cmd%" 2>nul
  	del /f /q "%output_cmd%" 2>nul
  	echo.
)

echo ================== ENCRYPT PROCESS ==================
echo Source file 	: %src_name%
set "src_size=0"
if exist "%src_file%" (
    for %%F in ("%src_file%") do set "src_size=%%~zF"
)

if "%src_size%"=="0" (
  	echo.
  	echo ERROR: File not found or size is 0 bytes.
  	echo.
	echo Press any key to exit...
	pause >nul
  	exit /b 1
)

for /f "delims=" %%S in ('powershell -NoProfile -Command "$s=%src_size%; if($s -ge 1073741824){'{0:N2} GB' -f ($s/1073741824)}elseif($s -ge 1048576){'{0:N2} MB' -f ($s/1048576)}else{'{0:N2} KB' -f ($s/1024)}"') do set "SIZE_STR=%%S"
echo Source size 	: !SIZE_STR! 
for /f "delims=" %%H in ('certutil -hashfile "%src_file%" SHA256 ^| findstr /v "hash" ^| findstr /r /v "^$"') do set "src_sha=%%H"
set "src_sha=%src_sha: =%"
echo Source SHA256 	: %src_sha%
echo.

if "!ENCRYPT_FLAG!"=="1" (
  	echo Process: Encrypting file with AES-256...
	powershell -ExecutionPolicy Bypass -NoProfile -Command "$_m=[math]; $password='!user_pass!'; $sw=New-Object Diagnostics.Stopwatch; $sw.Start(); $fileIn='%src_file%'; $fileOut='!temp_b64!'; $buffer = New-Object byte[] 65536; $fsIn = New-Object IO.FileStream($fileIn, [IO.FileMode]::Open, [IO.FileAccess]::Read); $fsOut = New-Object IO.FileStream($fileOut, [IO.FileMode]::Create, [IO.FileAccess]::Write); $salt=New-Object byte[] 16; (New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($salt); $iv=New-Object byte[] 16; (New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($iv); $fsOut.Write($salt, 0, 16); $fsOut.Write($iv, 0, 16); $kdf=New-Object System.Security.Cryptography.Rfc2898DeriveBytes($password, $salt, 10000); $key=$kdf.GetBytes(32); $aes=[System.Security.Cryptography.Aes]::Create(); $aes.Mode='CBC'; $aes.Padding='PKCS7'; $aes.Key=$key; $aes.IV=$iv; $cs=New-Object System.Security.Cryptography.CryptoStream($fsOut, $aes.CreateEncryptor(), [System.Security.Cryptography.CryptoStreamMode]::Write); $sentinelBytes = [Text.Encoding]::ASCII.GetBytes('__SECURE_ENCODE_MAGIC_BYTES_OK__'); $cs.Write($sentinelBytes, 0, $sentinelBytes.Length); $totalSize = $fsIn.Length; $totalRead = 0; $lp = -1; while (($read = $fsIn.Read($buffer, 0, $buffer.Length)) -gt 0) { $cs.Write($buffer, 0, $read); $totalRead += $read; $pct = [Math]::Floor(($totalRead / $totalSize) * 100); if ($pct -ne $lp) { $barLen = [Math]::Min(30, [Math]::Floor($pct/3.3)); $bar = '=' * $barLen; $space = ' ' * (30 - $barLen); Write-Host \"`rProgress: [$bar$space] $pct%%\" -NoNewline; $lp = $pct; } }; Write-Host \"`rProgress: [\" ('='*30)\"] 100%%\"; $cs.Close(); $fsOut.Close(); $fsIn.Close(); $aes.Clear(); $sw.Stop(); $ts=$sw.Elapsed; if($ts.TotalMinutes -ge 1){ Write-Host ('Time: {0} minutes {1:F0} seconds' -f $_m::Floor($ts.TotalMinutes),$ts.Seconds) }else{ Write-Host ('Time: {0:F2} seconds' -f $ts.TotalSeconds) }"
	set "IS_XORED=0"
) else (
	del "%TEMP_XOR_FLAG%" 2>nul
	set "IS_XORED=0"
  	powershell -ExecutionPolicy Bypass -NoProfile -Command "function Is-TextFile($filePath) { $blockSize = 4096; $buffer = New-Object byte[] $blockSize; try { $fs = [IO.File]::OpenRead($filePath); $read = $fs.Read($buffer, 0, $blockSize); $fs.Close(); if ($read -eq 0) { return $true }; for ($i = 0; $i -lt $read; $i++) { if ($buffer[$i] -eq 0) { return $false } }; return $true; } catch { return $false } }; $_m=[math]; $sw=[Diagnostics.Stopwatch]::StartNew(); $fileIn='%src_file%'; $fileOut='!temp_b64!'; if (Is-TextFile($fileIn)) { Write-Host 'Applying XOR obfuscation...'; $key = [Text.Encoding]::ASCII.GetBytes('%XOR_KEY%'); $keyLen = $key.Length; $fsIn = New-Object IO.FileStream($fileIn, [IO.FileMode]::Open); $fsOut = New-Object IO.FileStream($fileOut, [IO.FileMode]::Create); $buffer = New-Object byte[] 65536; $keyIndex = 0; $totalSize = $fsIn.Length; $totalRead = 0; $lp = -1; while (($read = $fsIn.Read($buffer, 0, $buffer.Length)) -gt 0) { for ($i = 0; $i -lt $read; $i++) { $buffer[$i] = $buffer[$i] -bxor $key[$keyIndex]; $keyIndex = ($keyIndex + 1) %% $keyLen }; $fsOut.Write($buffer, 0, $read); $totalRead += $read; $pct = [Math]::Floor(($totalRead / $totalSize) * 100); if ($pct -ne $lp) { $barLen = [Math]::Min(30, [Math]::Floor($pct/3.3)); $bar = '=' * $barLen; $space = ' ' * (30 - $barLen); Write-Host \"`rProgress: [$bar$space] $pct%%\" -NoNewline; $lp = $pct; } }; Write-Host \"`rProgress: [\" ('='*30)\"] 100%%\"; $fsOut.Close(); $fsIn.Close(); [IO.File]::WriteAllText('%TEMP_XOR_FLAG%', '1'); } else { Write-Host 'Copying raw data...'; $fsIn = New-Object IO.FileStream($fileIn, [IO.FileMode]::Open); $fsOut = New-Object IO.FileStream($fileOut, [IO.FileMode]::Create); $buffer = New-Object byte[] 65536; $totalSize = $fsIn.Length; $totalRead = 0; $lp = -1; while (($read = $fsIn.Read($buffer, 0, $buffer.Length)) -gt 0) { $fsOut.Write($buffer, 0, $read); $totalRead += $read; $pct = [Math]::Floor(($totalRead / $totalSize) * 100); if ($pct -ne $lp) { $barLen = [Math]::Min(30, [Math]::Floor($pct/3.3)); $bar = '=' * $barLen; $space = ' ' * (30 - $barLen); Write-Host \"`rProgress: [$bar$space] $pct%%\" -NoNewline; $lp = $pct; } }; Write-Host \"`rProgress: [\" ('='*30)\"] 100%%\"; $fsOut.Close(); $fsIn.Close(); [IO.File]::WriteAllText('%TEMP_XOR_FLAG%', '0'); }; $sw.Stop(); $ts=$sw.Elapsed; Write-Host ('Time: {0:F2} seconds' -f $ts.TotalSeconds)"

  	if exist "%TEMP_XOR_FLAG%" (
  		for /f "delims=" %%F in ('type "%TEMP_XOR_FLAG%"') do set "IS_XORED=%%F"
  	)
  	if not defined IS_XORED set "IS_XORED=0"
  	del "%TEMP_XOR_FLAG%" 2>nul
)

for %%F in ("%temp_b64%") do set "b64_size=%%~zF"
for /f "delims=" %%S in ('powershell -NoProfile -Command "$s=%b64_size%; if($s -ge 1GB){'{0:N2} GB' -f ($s/1GB)}elseif($s -ge 1MB){'{0:N2} MB' -f ($s/1MB)}else{'{0:N2} KB' -f ($s/1KB)}"') do set "B64_SIZE_STR=%%S"
echo.
echo Encrypted data size: !B64_SIZE_STR! ^(%b64_size% bytes^)
echo ================== ENCRYPT PROCESS ==================

:: === CREATE DECRYPT FILE ===
echo.
echo Creating decrypt file...

if exist "%output_cmd%" (
    attrib -R "%output_cmd%" 2>nul
    del /f /q "%output_cmd%" 2>nul
)

echo @echo off >> "%output_cmd%"
echo @title SecureEncrypt (AES-256 Encrypt ^^^& Decrypt^) >> "%output_cmd%"
echo @setlocal enabledelayedexpansion >> "%output_cmd%"
echo @pushd %%~dp0 >> "%output_cmd%"
echo. >> "%output_cmd%"
for /f "delims=" %%B in ('powershell -NoProfile -Command "$fileName='%src_name%'; $bytes=[Text.Encoding]::UTF8.GetBytes($fileName); [Convert]::ToBase64String($bytes)"') do set "FNB64=%%B"
echo set "FILE_B64=!FNB64!" >> "%output_cmd%"
echo set "expected_sha=%src_sha%" >> "%output_cmd%"
echo set "IS_ENCRYPTED=!ENCRYPT_FLAG!" >> "%output_cmd%"
echo set "IS_XORED=!IS_XORED!" >> "%output_cmd%"
echo set "XOR_KEY=%XOR_KEY%" >> "%output_cmd%"
echo echo. >> "%output_cmd%"
echo echo SecureEncrypt (AES-256 Encrypt ^^^& Decrypt^) >> "%output_cmd%"
echo echo. >> "%output_cmd%"
echo echo https://github.com/abdullah-erturk >> "%output_cmd%"
echo echo. >> "%output_cmd%"
echo echo ================== DECRYPT PROCESS ================== >> "%output_cmd%"
echo echo Target file	: %%out_name%% >> "%output_cmd%"
echo echo Expected SHA256	: %%expected_sha%% >> "%output_cmd%"
echo echo Encryption	: !ENCRYPT_FLAG! (1 = Yes, 0 = No^) >> "%output_cmd%"
echo echo Encrypt date	: %date% %time% >> "%output_cmd%"
echo echo. >> "%output_cmd%"
echo. >> "%output_cmd%"
echo set "TEMP_PS=%%TEMP%%\decode_%%RANDOM%%.ps1" >> "%output_cmd%"
echo type NUL ^> "%%TEMP_PS%%" ^>nul >> "%output_cmd%"
echo echo param^([string]^$self^) ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^$ErrorActionPreference^='Stop' ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^$isEnc ^^^= ^([int]^$env:IS_ENCRYPTED -eq 1^) ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^$isXored ^^^= ^([int]^$env:IS_XORED -eq 1^) ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^$xorKeyBytes ^^^= [Text.Encoding]^^::ASCII.GetBytes^($env:XOR_KEY^) ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo try ^{ ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^$marker ^^^= [Text.Encoding]^^::ASCII.GetBytes(^"`r`n::DATA::`r`n^") ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^$outNameB64 ^^^= ^$env:FILE_B64 ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	try ^{ ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^$outNameBytes ^^^= [Convert]^^::FromBase64String^(^$outNameB64^) ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^$outName ^^^= [Text.Encoding]^^::UTF8.GetString^(^$outNameBytes^) ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^} catch ^{ ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	Write-Host ^"ERROR: Could not decode filename. Base64: ^$outNameB64^" -ForegroundColor Red ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	exit 1 ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^$outPath ^^^= Join-Path ^(Split-Path -Parent ^$self^) ^$outName ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	Write-Host ^"Target file: ^$outName^" ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	# STREAM-BASED READING - Find marker ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^$fs ^^^= [IO.File]^^::OpenRead(^$self^) ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^$found ^^^= -1L ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^$buffer ^^^= New-Object byte[] 8192 ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^$pos ^^^= 0L ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^$markerBuf ^^^= New-Object byte[] ^$marker.Length ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	while^(^$fs.Position -lt ^$fs.Length^)^^{ ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^$read ^^^= ^$fs.Read(^$buffer,0,^$buffer.Length^) ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	if^(^$read -le 0^)^^{ break ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	for^(^$i^=0^; ^$i -lt ^$read^; ^$i^^^+^^^+^)^^{ ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	^$markerBuf ^^^= ^$markerBuf^[1..^(^$markerBuf.Length-1^)^] ^^^+ ^$buffer^[^$i^] ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	^$match ^^^= ^$true ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	for^(^$j^=0^; ^$j -lt ^$marker.Length^; ^$j^^^+^^^+^)^^{ ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	^	if^(^$markerBuf^[^$j^] -ne ^$marker^[^$j^]^)^^{ ^$match ^^^= ^$false^; break ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	if^(^$match^)^^{ ^$found ^^^= ^$pos ^^^+ ^$i ^^^+ 1L^; break ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	if^(^$found -ge 0^)^^{ break ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^$pos ^^^+^^^= ^$read ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	if^(^$found -lt 0^)^^{ throw ^"DATA marker not found^" ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^$fs.Position ^^^= ^$found ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	if^(^$isEnc^)^^{ ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	Write-Host ^'This file is encrypted. Please enter your password:^' ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^$sp ^^^= Read-Host -AsSecureString -Prompt ^'Password^' ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^$bstr^^^=[Runtime.InteropServices.Marshal]^^::SecureStringToBSTR(^$sp^) ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^$pw^^^=[Runtime.InteropServices.Marshal]^^::PtrToStringAuto(^$bstr^) ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^[void]^[Runtime.InteropServices.Marshal]^^::ZeroFreeBSTR(^$bstr^) ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	# Read salt and IV ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^$salt ^^^= New-Object byte[] 16 ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^$iv 	^^^= New-Object byte[] 16 ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^[void]^$fs.Read(^$salt, 0, 16^) ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^[void]^$fs.Read(^$iv, 0, 16^) ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^$kdf ^^^= New-Object Security.Cryptography.Rfc2898DeriveBytes(^$pw,^$salt,10000^) ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^$key ^^^= ^$kdf.GetBytes^(32^) ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^$aes ^^^= [Security.Cryptography.Aes]^^::Create^() ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^$aes.Mode^='CBC'^; ^$aes.Padding^='PKCS7'^; ^$aes.Key^=^$key^; ^$aes.IV^=^$iv ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^$cs ^^^= $null ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^$fsOut ^^^= $null ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	try ^{ ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	^$fsOut ^^^= New-Object IO.FileStream^(^$outPath,[IO.FileMode]^^::Create^) ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	^$cs ^^^= New-Object Security.Cryptography.CryptoStream^(^$fs,^$aes.CreateDecryptor^(),[Security.Cryptography.CryptoStreamMode]^^::Read^) ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	^$expectedSentinel ^^^= ^'__SECURE_ENCODE_MAGIC_BYTES_OK__^' ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	^$decSentinelBuf ^^^= New-Object byte[] 32 ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	^$readCount ^^^= ^$cs.Read^(^$decSentinelBuf, 0, 32^) ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	^if ^(^$readCount -ne 32^) ^{ throw ^"File corrupted (Sentinel could not be read)^" ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	^$decryptedSentinelStr ^^^= [Text.Encoding]^^::ASCII.GetString^(^$decSentinelBuf^) ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	^if ^(^$decryptedSentinelStr -ne ^$expectedSentinel^) ^{ throw ^"Wrong password or corrupted file^" ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	^$buf ^^^= New-Object byte[] 65536 ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	^while ^((^$n = ^$cs.Read(^$buf, 0, ^$buf.Length^)^) -gt 0^) ^{ ^$fsOut.Write(^$buf, 0, ^$n^) ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^} catch [System.Security.Cryptography.CryptographicException] ^{ ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	Write-Host ^"Wrong password or corrupted file^" -ForegroundColor Red ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	if ^(^$fsOut^) ^{ ^$fsOut.Close^() ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	if ^(^$cs^) ^{ ^$cs.Close^() ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	if^(Test-Path ^$outPath^)^^{ Remove-Item ^$outPath -ErrorAction SilentlyContinue ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	exit 1 ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^} catch ^{ ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	^$errMsg = ^$_.Exception.Message ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	Write-Host ^"ERROR: ^$errMsg^" -ForegroundColor Red ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	if ^(^$fsOut^) ^{ ^$fsOut.Close^() ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	if ^(^$cs^) ^{ ^$cs.Close^() ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	if^(Test-Path ^$outPath^)^^{ Remove-Item ^$outPath -ErrorAction SilentlyContinue ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	exit 1 ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^} finally ^{ ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	if ^(^$fsOut^) ^{ ^$fsOut.Close^() ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	if ^(^$cs^) ^{ ^$cs.Close^() ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	if ^(^$aes^) ^{ ^$aes.Clear^() ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^} else ^{ ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^$fsOut ^^^= New-Object IO.FileStream^(^$outPath,[IO.FileMode]^^::Create^) ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	try ^{ ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	if ^(^$isXored^) ^{ ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	^	^$key = ^$xorKeyBytes; ^$keyLen = ^$key.Length; ^$keyIndex = 0 ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	^	^$buf = New-Object byte[] 65536 ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	^	while ^((^$read = ^$fs.Read(^$buf, 0, ^$buf.Length^)^) -gt 0^) ^{ ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	^	^	for (^$i = 0; ^$i -lt ^$read; ^$i++^) ^{ ^$buf[^$i] = ^$buf[^$i] -bxor ^$key[^$keyIndex]; ^$keyIndex = (^$keyIndex + 1^) %%%% ^$keyLen ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	^	^	^$fsOut.Write(^$buf, 0, ^$read^) ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	^	^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	^} else ^{ ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	^	^$buf ^^^= New-Object byte[] 65536 ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	^	while ^((^$n = ^$fs.Read(^$buf, 0, ^$buf.Length^)^) -gt 0^) ^{ ^$fsOut.Write(^$buf, 0, ^$n^) ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^} finally ^{ ^$fsOut.Close^() ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^$fs.Close^() ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	if^(Test-Path ^$outPath^)^^{ ^$size^^^=^(Get-Item ^$outPath^).Length^; ^$kb^^^=^[math^]^^::Round^(^$size/1KB^)^; Write-Host ^"File created: ^$kb KB^" -ForegroundColor Green ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	if^(Test-Path ^$outPath^)^^{ ^$s^^^=^(Get-Item ^$outPath^).Length^; ^$mb^^^=^"{0:N2} MB^" -f ^(^$s/1MB^); Write-Host ^("File size: {0}" -f ^$mb,^$s^) ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	if^(Test-Path ^$outPath^)^^{ ^$stream^^^=[IO.File]^^::OpenRead^(^$outPath^)^; ^$sha256^^^=New-Object Security.Cryptography.SHA256Managed^; ^$hashBytes^^^=^$sha256.ComputeHash^(^$stream^)^; ^$stream.Close^()^; ^$sb^^^=New-Object Text.StringBuilder^; foreach^(^$b in ^$hashBytes^)^^{ [void]^$sb.Append^(^$b.ToString^("x2"^)^) ^^}^; ^$sha^^^=^$sb.ToString^()^; Write-Host ^"Calculated SHA256: ^$sha^"^; if^(^$sha -ieq ^$env:expected_sha^)^^{ Write-Host ^"SHA256: SUCCESS^" -ForegroundColor Green ^} else ^{ Write-Host ^"SHA256: FAILED^" -ForegroundColor Red ^} ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^} catch [System.Security.Cryptography.CryptographicException] ^{ ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	if^(Test-Path ^$outPath^)^^{ Remove-Item ^$outPath -ErrorAction SilentlyContinue ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	exit 1 ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^} catch ^{ ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^$errMsg = ^$_.Exception.Message ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	Write-Host ^"ERROR: ^$errMsg^" -ForegroundColor Red ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	if^(Test-Path ^$outPath^)^^{ Remove-Item ^$outPath -ErrorAction SilentlyContinue ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	exit 1 ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo powershell -ExecutionPolicy Bypass -NoProfile -File "%%TEMP_PS%%" "%%~f0" >> "%output_cmd%"
echo del "%%TEMP_PS%%" 2^>nul >> "%output_cmd%"
echo. >> "%output_cmd%"

echo. >> "%output_cmd%"
echo echo ================== DECRYPT PROCESS ================== >> "%output_cmd%"
echo echo. >> "%output_cmd%"
echo echo Press any key to exit...>> "%output_cmd%"
echo pause ^>nul >> "%output_cmd%"
echo exit >> "%output_cmd%"
echo. >> "%output_cmd%"
echo. >> "%output_cmd%"
(echo ::DATA::) >> "%output_cmd%"

if not exist "%output_cmd%" (
  	echo.
  	echo ERROR: Decrypt file could not be created^!
	echo Press any key to exit...
	pause >nul
  	exit /b 1
)

echo Decrypt command file created successfully.
echo.

if not exist "%temp_b64%" (
  	echo ERROR: Binary file not found: %temp_b64%
	echo Press any key to exit...
	pause >nul
  	exit /b 1
)

for %%F in ("%temp_b64%") do set "bin_size=%%~zF"
for /f "delims=" %%S in ('powershell -NoProfile -Command "$s=%bin_size%; if($s -ge 1GB){'{0:N2} GB' -f ($s/1GB)}elseif($s -ge 1MB){'{0:N2} MB' -f ($s/1MB)}else{'{0:N2} KB' -f ($s/1KB)}"') do set "BIN_SIZE_STR=%%S"
echo Binary file size: !BIN_SIZE_STR! 
echo Writing binary data to Decrypt file, please wait...
echo.

copy /b "%output_cmd%" + "%temp_b64%" "%output_cmd%.tmp" >nul 2>&1
if errorlevel 1 (
  	echo ERROR: Binary data merge failed^!
	echo Press any key to exit...
	pause >nul
  	exit /b 1
)

move /y "%output_cmd%.tmp" "%output_cmd%" >nul
if errorlevel 1 (
  	echo ERROR: File replacement failed^!
	echo Press any key to exit...
	pause >nul
  	exit /b 1
)

del "%temp_b64%" 2>nul
if exist "%TEMP_XOR_FLAG%" del /f /q "%TEMP_XOR_FLAG%" 2>nul

for %%F in ("%output_cmd%") do set "final_size=%%~zF"
for /f "delims=" %%S in ('powershell -NoProfile -Command "$s=%final_size%; if($s -ge 1GB){'{0:N2} GB' -f ($s/1GB)}elseif($s -ge 1MB){'{0:N2} MB' -f ($s/1MB)}else{'{0:N2} KB' -f ($s/1KB)}"') do set "FINAL_SIZE_STR=%%S"
echo Decrypt file size: !FINAL_SIZE_STR! 

attrib +R "%output_cmd%"

echo.
echo SUCCESS - All operations completed.
echo.
echo Decrypt file: %output_cmd%
echo.
echo Process completed.
echo.
echo Press any key to exit...
pause >nul
exit /b 0