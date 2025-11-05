@echo off
title SecureEncode (AES-256 Encrypt ^& Decrypt^) by Abdullah ERTšRK
set "_V_SIG=c776dbb3f09f2182c6ad344b43b0f2fa5333c1154aec68c5be8e39e67ae52bd9"
setlocal enabledelayedexpansion

set "TEMP_SELF=%TEMP%\SecureEncode_verify_%RANDOM%.tmp"
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
    echo SecureEncode (AES-256 Encrypt ^& Decrypt^)
    echo.
    echo https://github.com/abdullah-erturk
    echo.
    echo ========================================================================
    echo             HATA: Komut Dosyas Btnl§ ˜hlali
    echo ========================================================================
    echo.
    echo Bu betik de§iŸtirildi veya bozuldu.
    echo Gvenlik nedeniyle yrtme durduruldu.
    echo.
    echo Expected Hash  : %_V_SIG%
    echo.
    echo ========================================================================
    echo.
    echo €kŸ i‡in herhangi bir tuŸa basn...
    pause >nul
    exit /b
)

attrib +R "%~f0"
title SecureEncode (AES-256 Encrypt ^& Decrypt^) by Abdullah ERTšRK
setlocal enabledelayedexpansion
echo.
echo SecureEncode (AES-256 Encrypt ^& Decrypt^)
echo.
echo https://github.com/abdullah-erturk
echo.

if "%~1"=="" (
ÿ 	mode con cols=90 lines=22
ÿ 	echo.
ÿ 	echo SecureEncode (AES-256 Encrypt ^& Decrypt^)
ÿ 	echo.
ÿ 	echo.
	echo Kurulum yapmadan da kullanabilirsiniz.
	echo.
	echo žifreleme iŸlemi i‡in ltfen bu betik dosyasna bir dosya srkleyin.
ÿ 	echo.
ÿ 	ÿ
ÿ 	net session >nul 2>&1
ÿ 	if errorlevel 1 (
		echo Kurulum i‡in Y”netici ayrcalklar gerekiyor.
		echo Y”netici izinleri isteniyor...
ÿ 	 	echo.
ÿ 	 	powershell -Command "Start-Process '%~f0' -Verb RunAs"
ÿ 	 	exit /b
ÿ 	)
ÿ 	 	 	
ÿ 	if exist "C:\Windows\SecureEncode.cmd" (
ÿ 	 	echo.
ÿ 	 	echo.
		echo SecureEncode sistemde zaten kurulu.
		echo.
		choice /C EH /M "Kaldrlmasn istiyor musunuz"
ÿ 	 	if !errorlevel! equ 1 (
ÿ 	 	 	echo.
			echo Kaldrlyor...
			del /f /q "C:\Windows\SecureEncode.cmd" >nul
			reg delete "HKCR\*\shell\SecureEncode" /f >nul
			echo.
			echo Kaldrma iŸlemi baŸaryla tamamland.
			echo.
		) else (
			echo.
			echo Kaldrma iŸlemi iptal edildi.
			echo.
		)
	) else (
		echo.
		echo.
		echo SecureEncode sistemde kurulu de§il.
		echo.
		choice /C EH /M "Yklenmesini ister misiniz"
		if !errorlevel! equ 1 (
			echo.
			echo Ykleniyor...
			copy /y "%~f0" "C:\Windows\SecureEncode.cmd" >nul
			reg add "HKCR\*\shell\SecureEncode" /ve /d "Dosyay žifrele (Gvenli Kodlama AES-256)" /f >nul
			reg add "HKCR\*\shell\SecureEncode" /v "Icon" /d "C:\Windows\system32\imageres.dll,54" /f >nul
			reg add "HKCR\*\shell\SecureEncode\command" /ve /d "\"C:\Windows\SecureEncode.cmd\" \"%%1\"" /f >nul
			echo.
			echo Ykleme baŸaryla tamamland.
			echo.
			echo Sa§ tk mens eklendi: "Dosyay žifrele (Gvenli Kodlama AES-256)"
			echo.
		) else (
			echo.
			echo Ykleme iptal edildi.
			echo.
		)
	)
	echo €kŸ i‡in herhangi bir tuŸa basn...
	pause >nul
	exit /b
)

:: === GUVENLIK KONTROLU ===
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
ÿ 	echo ========================== UYARI ==========================
ÿ 	echo.
ÿ 	echo Dosya konumu: %~f1
ÿ 	echo.
ÿ 	echo Bu dizin bir sistem klas”rdr.
ÿ 	echo Gvenlik nedeniyle bu dizinde Ÿifreleme yaplamaz.
ÿ 	echo.
ÿ 	echo ===========================================================
ÿ 	echo.
	echo €kŸ i‡in herhangi bir tuŸa basn...
	pause >nul
ÿ 	exit /b 1
)
:security_passed

echo Bu dosya i‡in bir Ÿifre belirleyin. (iste§e ba§l)
echo (žifre girmezseniz dosya SADECE binary veri (RAW) olarak paketlenir, ž˜FRELENMEZ)
echo.

set "user_pass="
for /f "delims=" %%p in ('powershell -ExecutionPolicy Bypass -NoProfile -Command "$securePass=Read-Host -AsSecureString -Prompt 'žifre (ENTER tuŸuna basarsanz Ÿifreleme atlanr)'; $bstr=[System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePass); $password=[System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr); [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) | Out-Null; Write-Output $password"') do (
ÿ 	set "user_pass=%%p"
)

set "ENCRYPT_FLAG=0"
if defined user_pass (
ÿ 	if not "!user_pass!"=="" (
ÿ 	 	set "ENCRYPT_FLAG=1"
ÿ 	 	echo.
ÿ 	 	echo žifre ayarland. Dosya AES-256 ile Ÿifrelenecek.
ÿ 	 	echo ™NEML˜: Bu žifreyi unutmayn.
ÿ 	) else (
ÿ 	 	echo.
ÿ 	 	echo žifre bos. Dosya ž˜FRELENMEYECEK.
ÿ 	)
) else (
ÿ 	echo.
ÿ 	echo žifre girilmedi. Dosya ž˜FRELENMEYECEK.
)
echo.
echo žifreleme durumu : !ENCRYPT_FLAG! (1 = žifreli, 0 = žifresiz)
timeout /t 2 >nul

set "src_file=%~1"
set "src_name=%~nx1"
set "output_name_only=%~n1"
set "output_cmd=%~dp1%output_name_only%_decode.cmd"
set "temp_b64=%~dp1%~n1.bin"

if exist "%output_cmd%" (
ÿ 	echo Mevcut Decrypt dosyas bulundu. Salt okunur ”zelli§i kaldrlyor...
ÿ 	attrib -R "%output_cmd%"
ÿ 	echo.
)

echo ================== ENCRYPT ˜žLEM˜ ==================
echo Kaynak dosya 	: %src_name%
for %%F in ("%src_file%") do set "src_size=%%~zF"
if "%src_size%"=="" set "src_size=0"

if "%src_size%"=="0" (
ÿ 	echo.
ÿ 	echo HATA: Dosya bulunamad veya boyutu 0 bayt.
ÿ 	echo.
	echo €kŸ i‡in herhangi bir tuŸa basn...
	pause >nul
ÿ 	exit /b 1
)

for /f "delims=" %%S in ('powershell -NoProfile -Command "$s=%src_size%; if($s -ge 1073741824){'{0:N2} GB' -f ($s/1073741824)}elseif($s -ge 1048576){'{0:N2} MB' -f ($s/1048576)}else{'{0:N2} KB' -f ($s/1024)}"') do set "SIZE_STR=%%S"
echo Kaynak boyutu 	: !SIZE_STR! 
for /f "delims=" %%H in ('certutil -hashfile "%src_file%" SHA256 ^| findstr /v "hash" ^| findstr /r /v "^$"') do set "src_sha=%%H"
set "src_sha=%src_sha: =%"
echo Kaynak SHA256 	: %src_sha%
echo.

if "!ENCRYPT_FLAG!"=="1" (
ÿ 	echo "Sre‡		: Dosya -> AES-256 -> Gecici Dosya..."
	powershell -ExecutionPolicy Bypass -NoProfile -Command "$_m=[math]; $password=$env:user_pass; $sw=New-Object Diagnostics.Stopwatch; $sw.Start(); $fileIn='%src_file%'; $fileOut='%temp_b64%'; $buffer = New-Object byte[] 65536; $fsIn = New-Object IO.FileStream($fileIn, [IO.FileMode]::Open, [IO.FileAccess]::Read); $fsOut = New-Object IO.FileStream($fileOut, [IO.FileMode]::Create, [IO.FileAccess]::Write); $salt=New-Object byte[] 16; (New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($salt); $iv=New-Object byte[] 16; (New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($iv); $fsOut.Write($salt, 0, 16); $fsOut.Write($iv, 0, 16); $kdf=New-Object System.Security.Cryptography.Rfc2898DeriveBytes($password, $salt, 10000); $key=$kdf.GetBytes(32); $aes=[System.Security.Cryptography.Aes]::Create(); $aes.Mode='CBC'; $aes.Padding='PKCS7'; $aes.Key=$key; $aes.IV=$iv; $cs=New-Object System.Security.Cryptography.CryptoStream($fsOut, $aes.CreateEncryptor(), [System.Security.Cryptography.CryptoStreamMode]::Write); $sentinelBytes = [Text.Encoding]::ASCII.GetBytes('__SECURE_ENCODE_MAGIC_BYTES_OK__'); $cs.Write($sentinelBytes, 0, $sentinelBytes.Length); $totalSize = $fsIn.Length; $totalRead = 0; $lp = -1; while (($read = $fsIn.Read($buffer, 0, $buffer.Length)) -gt 0) { $cs.Write($buffer, 0, $read); $totalRead += $read; $pct = [Math]::Floor(($totalRead / $totalSize) * 100); if ($pct -ne $lp) { $barLen = [Math]::Min(30, [Math]::Floor($pct/3.3)); $bar = '=' * $barLen; $space = ' ' * (30 - $barLen); Write-Host \"`r˜lerleme	: [$bar$space] $pct%%\" -NoNewline; $lp = $pct; } }; Write-Host \"`r˜lerleme	: [\" ('='*30)\"] 100%%\"; $cs.Close(); $fsOut.Close(); $fsIn.Close(); $aes.Clear(); $sw.Stop(); $ts=$sw.Elapsed; if($ts.TotalMinutes -ge 1){ Write-Host ('Sre		: {0} dakika {1:F0} saniye' -f $_m::Floor($ts.TotalMinutes),$ts.Seconds) }else{ Write-Host ('Sre		: {0:F2} saniye' -f $ts.TotalSeconds) }"
) else (
ÿ 	echo "Sre‡		: Dosya -> Gecici Dosya (Sifresiz, Ham Veri)..."
ÿ 	powershell -ExecutionPolicy Bypass -NoProfile -Command "$_m=[math]; $sw=[Diagnostics.Stopwatch]::StartNew(); $fileIn='%src_file%'; $fileOut='%temp_b64%'; Copy-Item $fileIn $fileOut -Force; $sw.Stop(); $ts=$sw.Elapsed; Write-Host ('Sre		: {0:F2} saniye' -f $ts.TotalSeconds)"
)

for %%F in ("%temp_b64%") do set "b64_size=%%~zF"
for /f "delims=" %%S in ('powershell -NoProfile -Command "$s=%b64_size%; if($s -ge 1GB){'{0:N2} GB' -f ($s/1GB)}elseif($s -ge 1MB){'{0:N2} MB' -f ($s/1MB)}else{'{0:N2} KB' -f ($s/1KB)}"') do set "B64_SIZE_STR=%%S"
echo.
echo žifreli veri boyutu: !B64_SIZE_STR! ^(%b64_size% bayt^)
echo ================== ENCRYPT ˜žLEM˜ ==================

:: === DECRYPT DOSYASI OLUSTURMA ===
echo.
echo Decrypt dosyas oluŸturuluyor...
echo chcp 1254 >nul > "%output_cmd%"
echo @echo off > "%output_cmd%"
echo @title SecureEncode (AES-256 Encrypt ^^^& Decrypt^) >> "%output_cmd%"
echo @setlocal enabledelayedexpansion >> "%output_cmd%"
echo @pushd %%~dp0 >> "%output_cmd%"
echo. >> "%output_cmd%"
for /f "delims=" %%B in ('powershell -NoProfile -Command "[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('%src_name%'))"') do set "FNB64=%%B"
echo set "FILE_B64=!FNB64!" >> "%output_cmd%"
echo set "expected_sha=%src_sha%" >> "%output_cmd%"
echo set "IS_ENCRYPTED=!ENCRYPT_FLAG!" >> "%output_cmd%"
echo echo. >> "%output_cmd%"
echo echo SecureEncode (AES-256 Encrypt ^^^& Decrypt^) >> "%output_cmd%"
echo echo. >> "%output_cmd%"
echo echo https://github.com/abdullah-erturk >> "%output_cmd%"
echo echo. >> "%output_cmd%"
echo echo ================== DECRYPT ˜žLEM˜ ================== >> "%output_cmd%"
echo set "out_name=" >> "%output_cmd%"
(echo powershell -NoProfile -Command "$p=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($env:FILE_B64)); Write-Output $p" ^> "%%TEMP%%\_name.tmp") >> "%output_cmd%"
(echo set /p out_name=^<"%%TEMP%%\_name.tmp") >> "%output_cmd%"
(echo del "%%TEMP%%\_name.tmp" 2^>nul) >> "%output_cmd%"
echo echo Hedef dosya	: %%out_name%% >> "%output_cmd%"
echo echo Beklenen SHA256	: %%expected_sha%% >> "%output_cmd%"
echo echo žifreleme	: !ENCRYPT_FLAG! (1 = Evet, 0 = Hayr^) >> "%output_cmd%"
echo echo Encrypt tarihi	: %date% %time% >> "%output_cmd%"
echo echo. >> "%output_cmd%"
echo. >> "%output_cmd%"

:: === PowerShell cozumleyiciyi satir satir yaz - STREAM TABANLI ===
echo set "TEMP_PS=%%TEMP%%\decode_%%RANDOM%%.ps1" >> "%output_cmd%"
echo type NUL ^> "%%TEMP_PS%%" ^>nul >> "%output_cmd%"
echo echo param^([string]^$self^) ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^$ErrorActionPreference^='Stop' ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^$isEnc ^^^= ^([int]^$env:IS_ENCRYPTED -eq 1^) ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo try ^{ ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^$marker ^^^= [Text.Encoding]^^::ASCII.GetBytes(^"`r`n::DATA::`r`n^") ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^$outPath ^^^= [Text.Encoding]^^::Unicode.GetString^([Convert]^^::FromBase64String^($env:FILE_B64^)^) ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	# STREAM TABANLI OKUMA - Marker'i bul ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
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
echo echo ^	^	Write-Host ^'Bu dosya sifreli. Lutfen sifrenizi girin:^' ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^$sp ^^^= Read-Host -AsSecureString -Prompt ^'Sifre^' ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^$bstr^^^=[Runtime.InteropServices.Marshal]^^::SecureStringToBSTR(^$sp^) ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^$pw^^^=[Runtime.InteropServices.Marshal]^^::PtrToStringAuto(^$bstr^) ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^[void]^[Runtime.InteropServices.Marshal]^^::ZeroFreeBSTR(^$bstr^) ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	# Salt ve IV oku ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
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
echo echo ^	^	^	^if ^(^$readCount -ne 32^) ^{ throw ^"Dosya bozuk (Sentinel okunamadi)^" ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	^$decryptedSentinelStr ^^^= [Text.Encoding]^^::ASCII.GetString^(^$decSentinelBuf^) ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	^if ^(^$decryptedSentinelStr -ne ^$expectedSentinel^) ^{ throw ^"Yanlis sifre veya bozuk dosya^" ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	^$buf ^^^= New-Object byte[] 65536 ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	^while^(^(^$n^^^=^$cs.Read^(^$buf,0,^$buf.Length^)^) -gt 0^)^^{ ^$fsOut.Write^(^$buf,0,^$n^) ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^} catch [System.Security.Cryptography.CryptographicException] ^{ ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	Write-Host ^"Yanlis sifre veya bozuk dosya^" -ForegroundColor Red ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	if ^(^$fsOut^) ^{ ^$fsOut.Close^() ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	if ^(^$cs^) ^{ ^$cs.Close^() ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	if^(Test-Path ^$outPath^)^^{ Remove-Item ^$outPath -ErrorAction SilentlyContinue ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	exit 1 ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^} catch ^{ ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	^$errMsg = ^$_.Exception.Message ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	Write-Host ^"HATA: ^$errMsg^" -ForegroundColor Red ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
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
echo echo ^	^	^	^$buf ^^^= New-Object byte[] 65536 ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^	while^(^(^$n^^^=^$fs.Read^(^$buf,0,^$buf.Length^)^) -gt 0^)^^{ ^$fsOut.Write^(^$buf,0,^$n^) ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^	^} finally ^{ ^$fsOut.Close^() ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^$fs.Close^() ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	if^(Test-Path ^$outPath^)^^{ ^$size^^^=^(Get-Item ^$outPath^).Length^; ^$kb^^^=^[math^]^^::Round^(^$size/1KB^)^; Write-Host ^"Dosya olusturuldu: ^$kb KB^" -ForegroundColor Green ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	if^(Test-Path ^$outPath^)^^{ ^$s^^^=^(Get-Item ^$outPath^).Length^; ^$mb^^^=^"{0:N2} MB^" -f ^(^$s/1MB^); Write-Host ^("Dosya boyutu: {0}" -f ^$mb,^$s^) ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	if^(Test-Path ^$outPath^)^^{ ^$stream^^^=[IO.File]^^::OpenRead^(^$outPath^)^; ^$sha256^^^=New-Object Security.Cryptography.SHA256Managed^; ^$hashBytes^^^=^$sha256.ComputeHash^(^$stream^)^; ^$stream.Close^()^; ^$sb^^^=New-Object Text.StringBuilder^; foreach^(^$b in ^$hashBytes^)^^{ [void]^$sb.Append^(^$b.ToString^("x2"^)^) ^^}^; ^$sha^^^=^$sb.ToString^()^; Write-Host ^"Calculated SHA256: ^$sha^"^; if^(^$sha -ieq ^$env:expected_sha^)^^{ Write-Host ^"SHA256: SUCCESS^" -ForegroundColor Green ^} else ^{ Write-Host ^"SHA256: FAILED^" -ForegroundColor Red ^} ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^} catch [System.Security.Cryptography.CryptographicException] ^{ ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	if^(Test-Path ^$outPath^)^^{ Remove-Item ^$outPath -ErrorAction SilentlyContinue ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	exit 1 ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^} catch ^{ ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	^$errMsg = ^$_.Exception.Message ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	Write-Host ^"nHATA: ^$errMsg^" -ForegroundColor Red ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	if^(Test-Path ^$outPath^)^^{ Remove-Item ^$outPath -ErrorAction SilentlyContinue ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^	exit 1 ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo echo ^} ^>^> "%%TEMP_PS%%" >> "%output_cmd%"
echo powershell -ExecutionPolicy Bypass -NoProfile -File "%%TEMP_PS%%" "%%~f0" >> "%output_cmd%"
echo del "%%TEMP_PS%%" 2^>nul >> "%output_cmd%"
echo. >> "%output_cmd%"

echo. >> "%output_cmd%"
echo echo ================== DECRYPT ˜žLEM˜ ================== >> "%output_cmd%"
echo echo. >> "%output_cmd%"
echo echo €kŸ i‡in herhangi bir tuŸa basn...>> "%output_cmd%"
echo pause ^>nul >> "%output_cmd%"
echo exit >> "%output_cmd%"
echo. >> "%output_cmd%"
echo. >> "%output_cmd%"
(echo ::DATA::) >> "%output_cmd%"

if not exist "%output_cmd%" (
ÿ 	echo.
ÿ 	echo HATA: Decrypt dosyas oluŸturulamad^!
	echo €kŸ i‡in herhangi bir tuŸa basn...
	pause >nul
ÿ 	exit /b 1
)

echo Decrypt komut dosyas baŸarl Ÿekilde oluŸturuldu.
echo.

if not exist "%temp_b64%" (
ÿ 	echo HATA: Binary dosya bulunamad: %temp_b64%
	echo €kŸ i‡in herhangi bir tuŸa basn...
	pause >nul
ÿ 	exit /b 1
)

for %%F in ("%temp_b64%") do set "bin_size=%%~zF"
for /f "delims=" %%S in ('powershell -NoProfile -Command "$s=%bin_size%; if($s -ge 1GB){'{0:N2} GB' -f ($s/1GB)}elseif($s -ge 1MB){'{0:N2} MB' -f ($s/1MB)}else{'{0:N2} KB' -f ($s/1KB)}"') do set "BIN_SIZE_STR=%%S"
echo Binary dosya boyutu: !BIN_SIZE_STR! 
echo Binary veri Decrypt dosyasna yazlyor, ltfen bekleyin...
echo.

copy /b "%output_cmd%" + "%temp_b64%" "%output_cmd%.tmp" >nul 2>&1
if errorlevel 1 (
ÿ 	echo HATA: Binary veri birleŸtirme baŸarsz^!
	echo €kŸ i‡in herhangi bir tuŸa basn...
	pause >nul
ÿ 	exit /b 1
)

move /y "%output_cmd%.tmp" "%output_cmd%" >nul
if errorlevel 1 (
ÿ 	echo HATA: Dosya de§iŸtirme baŸarsz^!
	echo €kŸ i‡in herhangi bir tuŸa basn...
	pause >nul
ÿ 	exit /b 1
)

del "%temp_b64%" 2>nul

for %%F in ("%output_cmd%") do set "final_size=%%~zF"
for /f "delims=" %%S in ('powershell -NoProfile -Command "$s=%final_size%; if($s -ge 1GB){'{0:N2} GB' -f ($s/1GB)}elseif($s -ge 1MB){'{0:N2} MB' -f ($s/1MB)}else{'{0:N2} KB' -f ($s/1KB)}"') do set "FINAL_SIZE_STR=%%S"
echo Decrypt dosya boyutu: !FINAL_SIZE_STR! 

attrib +R "%output_cmd%"

echo.
echo BAžARILI - Tm iŸlemler tamamland.
echo.
echo Decrypt dosyas: %output_cmd%
echo.
echo €kŸ i‡in herhangi bir tuŸa basn...
pause >nul