@echo off
title Base64 Encrypt ^& Decrypt (AES-256 Encrypted) by Abdullah ERTURK
setlocal enabledelayedexpansion

echo.
echo Base64 Encrypt ^& Decrypt (AES-256 Encrypted^)
echo.
echo https://github.com/abdullah-erturk
echo.

if "%~1"=="" (
	mode con cols=90 lines=21
	echo.
	echo Base64 Encrypt ^& Decrypt (AES-256 Encrypted^)
	echo.
	echo Kurulum yapmadan da kullanabilirsiniz.
	echo.
	echo Kodlamak i‡in ltfen bu betik dosyasna bir dosya srkleyin.
	echo.
	
	net session >nul 2>&1
	if errorlevel 1 (
		echo Kurulum i‡in Y”netici ayrcalklar gerekiyor.
		echo Y”netici izinleri isteniyor...
		echo.
		powershell -Command "Start-Process '%~f0' -Verb RunAs"
		exit /b
	)
		
	if exist "C:\Windows\SecureEncode.cmd" (
		echo.
		echo.
		echo SecureEncode sistemde zaten kurulu.
		echo.
		choice /C EH /M "Kaldrlmasn istiyor musunuz"
		if !errorlevel! equ 1 (
			echo.
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
	echo Devam etmek i‡in herhangi bir tuŸa basn...
	pause >nul
	exit /b
)

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
	echo ========================== UYARI ==========================
	echo.
	echo Dosya konumu: %~f1
	echo.
	echo Bu dizin bir sistem klas”rdr.
	echo Gvenlik nedeniyle bu dizinde Ÿifreleme yaplamaz.
	echo.
	echo Yasakl konumlar:
	echo    - C:\* ana dizini
	echo    - C:\Windows\*
	echo    - C:\Program Files\*
	echo    - C:\Program Files (x86^)\*
	echo    - C:\ProgramData\*
	echo    - System Volume Information (tm srcler^)
	echo    - $Recycle.Bin (tm srcler^)
	echo.
	echo ˜zin verilen konumlar:
	echo    - C:\Users\%username%\* (Masast, Belgeler, ˜ndirilenler vb.^)
	echo    - D:\*, E:\*, F:\* (di§er tm srcler^)
	echo.
	echo ===========================================================
	echo.
	echo Devam etmek i‡in herhangi bir tuŸa basn...
	pause >nul
	exit /b 1
)
:security_passed

:: === Sifre B”lm (˜ste§e Ba§l) ===
echo Ltfen bu dosya i‡in bir Ÿifre belirleyin.
echo (ENTER'a basarsanz Ÿifreleme atlanr. Dosya sadece GZip ile skŸtrlp base64 yaplr.)
echo.

:: PowerShell kullanarak gvenli bir Ÿekilde parola aln (*** g”rntlenir)
echo Ltfen Ÿifrenizi girin (˜ste§e ba§l)
set "user_pass="
for /f "delims=" %%p in ('powershell -ExecutionPolicy Bypass -NoProfile -Command "$securePass=Read-Host -AsSecureString -Prompt 'žifre (BoŸ brakmak i‡in ENTER)'; $bstr=[System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePass); $password=[System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr); [void][System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr); [void]$securePass.Dispose(); Write-Output $password"') do (
	set "user_pass=%%p"
)

set "ENCRYPT_FLAG=1"
if "!user_pass!"=="" (
	set "ENCRYPT_FLAG=0"
	echo.
	echo žifre ayarlanmad. Dosya ž˜FRELENMEYECEK.
) else (
	echo.
	echo žifre ayarland. Ltfen unutmayn.
)
echo.
:: === Sifre B”lm Bitti ===

set "src_file=%~1"
set "src_name=%~nx1"
set "output_name_only=%~n1"
set "output_cmd=%~dp1%output_name_only%_decode.cmd"
set "temp_b64=%~dp1%~n1.b64"

if exist "%output_cmd%" (
    echo Mevcut Decode dosyas bulundu. Salt okunur ”zelli§i kaldrlyor...
    attrib -R "%output_cmd%"
    echo.
)

echo ================== ENCODE ˜žLEM˜ ==================
echo Kaynak dosya	: %src_name%
for %%F in ("%src_file%") do set "src_size=%%~zF"
if "%src_size%"=="" set "src_size=0"

if "%src_size%"=="0" (
	echo.
	echo HATA: Dosya bulunamad veya boyutu 0 bayt.
	echo Kontrol edilen yol: "%src_file%"
	echo.
	echo E§er dosya adnda boŸluk varsa, komut satrnda trnak kullann:
	echo ™rnek: %~n0 "Dosyam.pdf"
	echo Veya dosyay do§rudan betik zerine srkleyin.
	echo.
	echo Devam etmek i‡in herhangi bir tuŸa basn...
	pause >nul
	exit /b
)

set /a "size_mb=%src_size% / 1048576"
set /a "size_kb=(%src_size% %% 1048576) / 1024"
if %src_size% GEQ 1048576 (
	echo Kaynak boyutu	: !size_mb!.!size_kb! MB ^(!src_size! bayt^)
) else (
	set /a "size_kb=%src_size% / 1024"
	echo Kaynak boyutu	: !size_kb! KB ^(!src_size! bayt^)
)
for /f "delims=" %%H in ('certutil -hashfile "%src_file%" SHA256 ^| findstr /v "hash" ^| findstr /r /v "^$"') do set "src_sha=%%H"
set "src_sha=%src_sha: =%"
echo Kaynak SHA256	: %src_sha%
echo.

:: === ˜stege Ba§l žifreleme Blo§u ===
if "!ENCRYPT_FLAG!"=="1" (
	echo "SkŸtrlyor, Base64 olarak kodlanyor ve Ÿifreleniyor (AES-256)..."
	:: AES ENCRYPTED YOLU
	powershell -ExecutionPolicy Bypass -NoProfile -Command "$_m=[math]; $password=$env:user_pass; $sw=[Diagnostics.Stopwatch]::StartNew(); $file='%src_file%'; $out='%temp_b64%'; $bytes=[IO.File]::ReadAllBytes($file); $originalSize=$bytes.Length; Write-Host 'Orijinal boyut	: ' -NoNewline; if($originalSize -ge 1MB){ Write-Host ('{0:F2} MB ({1} bytes)' -f ($originalSize/1MB),$originalSize) }else{ Write-Host ('{0:F2} KB ({1} bytes)' -f ($originalSize/1KB),$originalSize) }; $ms=New-Object IO.MemoryStream; $gz=New-Object IO.Compression.GZipStream -ArgumentList @($ms,[IO.Compression.CompressionMode]::Compress); $gz.Write($bytes,0,$bytes.Length); $gz.Close(); $compressed=$ms.ToArray(); $ms.Close(); $bytes=0; $compressedSize=$compressed.Length; Write-Host 'SkŸtrlmŸ boyut: ' -NoNewline; if($compressedSize -ge 1MB){ Write-Host ('{0:F2} MB ({1} bytes)' -f ($compressedSize/1MB),$compressedSize) }else{ Write-Host ('{0:F2} KB ({1} bytes)' -f ($compressedSize/1KB),$compressedSize) }; $ratio=$_m::Round((1-($compressedSize/$originalSize))*100,1); Write-Host ('SkŸtrma	: {0}%%' -f $ratio); Write-Host ''; $salt=New-Object byte[] 16; (New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($salt); $iv=New-Object byte[] 16; (New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($iv); $kdf=New-Object System.Security.Cryptography.Rfc2898DeriveBytes -ArgumentList @($password, $salt, 10000); $key=$kdf.GetBytes(32); $aes=[System.Security.Cryptography.Aes]::Create(); $aes.Mode='CBC'; $aes.Padding='PKCS7'; $aes.Key=$key; $aes.IV=$iv; $encryptor=$aes.CreateEncryptor(); $msCrypt=New-Object IO.MemoryStream; $cs=New-Object System.Security.Cryptography.CryptoStream -ArgumentList @($msCrypt, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write); $cs.Write($compressed, 0, $compressed.Length); $cs.FlushFinalBlock(); $cs.Close(); $encryptedData=$msCrypt.ToArray(); $msCrypt.Close(); $compressed=0; $aes.Clear(); Write-Host \"`r˜lerleme: [\" ('='*30) \"] 100%%\"; $txtOut=New-Object IO.StreamWriter -ArgumentList @($out,[System.Text.Encoding]::Default); $txtOut.WriteLine('-----BEGIN CERTIFICATE-----'); $txtOut.Flush(); $b64t = New-Object System.Security.Cryptography.ToBase64Transform; $b64Stream=New-Object System.Security.Cryptography.CryptoStream -ArgumentList @($txtOut.BaseStream, $b64t, [System.Security.Cryptography.CryptoStreamMode]::Write, $true); $b64Stream.Write($salt,0,$salt.Length); $b64Stream.Write($iv,0,$iv.Length); $b64Stream.Write($encryptedData,0,$encryptedData.Length); $b64Stream.FlushFinalBlock(); $b64Stream.Close(); $txtOut.WriteLine(); $txtOut.WriteLine('-----END CERTIFICATE-----'); $txtOut.Close(); $sw.Stop(); $ts=$sw.Elapsed; if($ts.TotalMinutes -ge 1){ Write-Host ('Sre: {0} dakika {1:F0} saniye' -f $_m::Floor($ts.TotalMinutes),$ts.Seconds) }else{ Write-Host ('Sre: {0:F2} saniye' -f $ts.TotalSeconds) }"
) else (
	echo "SkŸtrlyor ve Base64 olarak kodlanyor (žifresiz)..."
	:: ž˜FRELENMEM˜ž YOL (Yalnzca GZip + Base64)
	powershell -ExecutionPolicy Bypass -NoProfile -Command "$_m=[math]; $sw=[Diagnostics.Stopwatch]::StartNew(); $file='%src_file%'; $out='%temp_b64%'; $bytes=[IO.File]::ReadAllBytes($file); $originalSize=$bytes.Length; Write-Host 'Orijinal boyut	: ' -NoNewline; if($originalSize -ge 1MB){ Write-Host ('{0:F2} MB ({1} bytes)' -f ($originalSize/1MB),$originalSize) }else{ Write-Host ('{0:F2} KB ({1} bytes)' -f ($originalSize/1KB),$originalSize) }; $ms=New-Object IO.MemoryStream; $gz=New-Object IO.Compression.GZipStream -ArgumentList @($ms,[IO.Compression.CompressionMode]::Compress); $gz.Write($bytes,0,$bytes.Length); $gz.Close(); $compressed=$ms.ToArray(); $ms.Close(); $bytes=0; $compressedSize=$compressed.Length; Write-Host 'SkŸtrlmŸ boyut: ' -NoNewline; if($compressedSize -ge 1MB){ Write-Host ('{0:F2} MB ({1} bytes)' -f ($compressedSize/1MB),$compressedSize) }else{ Write-Host ('{0:F2} KB ({1} bytes)' -f ($compressedSize/1KB),$compressedSize) }; $ratio=$_m::Round((1-($compressedSize/$originalSize))*100,1); Write-Host ('SkŸtrma	: {0}%%' -f $ratio); Write-Host ''; Write-Host \"`r˜lerleme: [\" ('='*30) \"] 100%%\"; $txtOut=New-Object IO.StreamWriter -ArgumentList @($out,[System.Text.Encoding]::Default); $txtOut.WriteLine('-----BEGIN CERTIFICATE-----'); $txtOut.Flush(); $b64t = New-Object System.Security.Cryptography.ToBase64Transform; $b64Stream=New-Object System.Security.Cryptography.CryptoStream -ArgumentList @($txtOut.BaseStream, $b64t, [System.Security.Cryptography.CryptoStreamMode]::Write, $true); $b64Stream.Write($compressed,0,$compressed.Length); $b64Stream.FlushFinalBlock(); $b64Stream.Close(); $txtOut.WriteLine(); $txtOut.WriteLine('-----END CERTIFICATE-----'); $txtOut.Close(); $sw.Stop(); $ts=$sw.Elapsed; if($ts.TotalMinutes -ge 1){ Write-Host ('Sre: {0} dakika {1:F0} saniye' -f $_m::Floor($ts.TotalMinutes),$ts.Seconds) }else{ Write-Host ('Sre: {0:F2} saniye' -f $ts.TotalSeconds) }"
)

for %%F in ("%temp_b64%") do set "b64_size=%%~zF"
set /a "b64_mb=!b64_size! / 1048576"
set /a "b64_kb=(!b64_size! %% 1048576) / 1024"
if !b64_size! GEQ 1048576 (
	echo B64 dosya boyutu : !b64_mb!.!b64_kb! MB ^(!b64_size! bayt^)
) else (
	set /a "b64_kb=!b64_size! / 1024"
	echo B64 dosya boyutu : !b64_kb! KB ^(!b64_size! bayt^)
)
echo ================== ENCODE ˜žLEM˜ ==================

:: === Decode Beti§i ===
echo @echo off > "%output_cmd%"
echo title Base64 Encrypt ^^^& Decrypt (AES-256 Encrypted) >> "%output_cmd%"
echo setlocal enabledelayedexpansion >> "%output_cmd%"
echo pushd %%~dp0 >> "%output_cmd%"
echo set "file=%src_name%" >> "%output_cmd%"
echo set "expected_sha=%src_sha%" >> "%output_cmd%"
echo set "IS_ENCRYPTED=!ENCRYPT_FLAG!" >> "%output_cmd%"
echo echo. >> "%output_cmd%"
echo echo Base64 Encrypt ^^^& Decrypt (AES-256 Encrypted)>> "%output_cmd%"
echo echo. >> "%output_cmd%"
echo echo https://github.com/abdullah-erturk >> "%output_cmd%"
echo echo. >> "%output_cmd%"
echo echo ================== DECODE ˜žLEM˜ ================== >> "%output_cmd%"
echo echo Hedef dosya	: %%file%% >> "%output_cmd%"
echo echo. >> "%output_cmd%"
echo. >> "%output_cmd%"
echo powershell -ExecutionPolicy Bypass -NoProfile -Command "$_m=[math]; $ProgressPreference='SilentlyContinue'; $sw=[Diagnostics.Stopwatch]::StartNew(); $c=$false; $sb=New-Object System.Text.StringBuilder -ArgumentList 2000000; $lines=@(Get-Content '%%~f0'); $t=$lines.Count; $i=0; $lp=-1; foreach($ln in $lines){ $i++; if($ln -eq '-----BEGIN CERTIFICATE-----'){ $c=$true; continue } if($ln -eq '-----END CERTIFICATE-----'){ $c=$false; break } if($c){ [void]$sb.Append($ln) } $pct=$_m::Floor(($i/$t)*100); if($pct -ne $lp -and ($pct %%%% 5) -eq 0){ $barLen=$_m::Min(30,$_m::Floor($pct/2)); $bar='='*$barLen; $space=' '*(30-$barLen); Write-Host `r˜lerleme: [$bar$space] $pct%%%% -NoNewline; $lp=$pct } } Write-Host `r˜lerleme: [ ('='*30) ] 100%%%%; try { $combinedData=[Convert]::FromBase64String($sb.ToString()); if($env:IS_ENCRYPTED -eq "1") { Write-Host 'Bu dosya Ÿifre korumal.'; $securePass=Read-Host -Prompt 'Ltfen Ÿifreyi girin' -AsSecureString; $bstr=[System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePass); $password=[System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr); [void][System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr); [void]$securePass.Dispose(); $salt=New-Object byte[] 16; $iv=New-Object byte[] 16; $encryptedData=New-Object byte[] ($combinedData.Length - 32); [Array]::Copy($combinedData, 0, $salt, 0, 16); [Array]::Copy($combinedData, 16, $iv, 0, 16); [Array]::Copy($combinedData, 32, $encryptedData, 0, $encryptedData.Length); $kdf=New-Object System.Security.Cryptography.Rfc2898DeriveBytes -ArgumentList @($password, $salt, 10000); $key=$kdf.GetBytes(32); $aes=[System.Security.Cryptography.Aes]::Create(); $aes.Mode='CBC'; $aes.Padding='PKCS7'; $aes.Key=$key; $aes.IV=$iv; $decryptor=$aes.CreateDecryptor(); $msCrypt=New-Object IO.MemoryStream -ArgumentList (,$encryptedData); $cs=New-Object System.Security.Cryptography.CryptoStream -ArgumentList @($msCrypt, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read); $msDecompressed=New-Object IO.MemoryStream; $buffer = New-Object byte[] 4096; while (($read = $cs.Read($buffer, 0, $buffer.Length)) -gt 0) { $msDecompressed.Write($buffer, 0, $read) }; $compressed=$msDecompressed.ToArray(); $msCrypt.Close(); $cs.Close(); $msDecompressed.Close(); $aes.Clear(); } else { Write-Host 'Dosya Ÿifreli de§il, skŸtrma a‡lyor...'; $compressed=$combinedData; } $ms=New-Object IO.MemoryStream -ArgumentList (,$compressed); $gz=New-Object IO.Compression.GZipStream -ArgumentList @($ms,[IO.Compression.CompressionMode]::Decompress); $output=New-Object IO.MemoryStream; $buffer = New-Object byte[] 4096; while (($read = $gz.Read($buffer, 0, $buffer.Length)) -gt 0) { $output.Write($buffer, 0, $read) }; $decompressed=$output.ToArray(); $gz.Close(); $ms.Close(); $output.Close(); [IO.File]::WriteAllBytes('%%file%%',$decompressed); $sw.Stop(); $ts=$sw.Elapsed; if($ts.TotalMinutes -ge 1){ Write-Host ('Sre: {0} dakika {1:F0} saniye' -f $_m::Floor($ts.TotalMinutes),$ts.Seconds) }else{ Write-Host ('Sre: {0:F2} saniye' -f $ts.TotalSeconds) }; if(Test-Path '%%file%%'){ Write-Host 'BAžARILI	  : %%file%% oluŸturuldu' } } catch [System.Security.Cryptography.CryptographicException] { Write-Host `nHATA: žifre yanlŸ veya dosya bozuk. -ForegroundColor Red } catch { Write-Host `nBEKLENMEYEN HATA: $_ -ForegroundColor Red }" >> "%output_cmd%"
echo. >> "%output_cmd%"
echo powershell -ExecutionPolicy Bypass -NoProfile -Command "if(Test-Path '%%file%%') { $sha = (Get-FileHash -Algorithm SHA256 '%%file%%').Hash; if($sha -eq '%src_sha%'){ Write-Host 'SHA256 DO¦RULANDI : Dosya btnl§ tamam.' }else{ Write-Host 'SHA256 UYUžMAZLI¦I: Dosya bozuk olabilir.' } }" >> "%output_cmd%"
echo. >> "%output_cmd%"
echo echo ================== DECODE ˜žLEM˜ ================== >> "%output_cmd%"
echo echo. >> "%output_cmd%"
echo. >> "%output_cmd%"
echo echo Devam etmek i‡in herhangi bir tuŸa basn...>> "%output_cmd%"
echo pause ^>nul >> "%output_cmd%"
echo goto :eof >> "%output_cmd%"

type "%temp_b64%" >> "%output_cmd%"
del "%temp_b64%"

attrib +R "%output_cmd%"

echo.
echo Decode dosyas i‡in Salt Okunur ”zelli§i ayarland.
echo.
echo Decode dosyas: %output_cmd%
echo.
echo Devam etmek i‡in herhangi bir tuŸa basn...
pause >nul