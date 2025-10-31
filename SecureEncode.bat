@echo off
title Base64 Encrypt ^& Decrypt (AES-256 Encrypted) by Abdullah ERTURK
setlocal enabledelayedexpansion

echo.
echo Base64 Encrypt ^& Decrypt (AES-256 Encrypted)
echo.
echo https://github.com/abdullah-erturk
echo.

if "%~1"=="" (
    echo Please drag a file to this batch file to encode it.
    echo.
    pause
    exit /b
)

:: === Password Section (Optional) ===
echo Please set a password for this file.
echo (Press ENTER to skip encryption. File will be GZipped only.)
echo.

:: Get password securely using PowerShell (displays ***)
echo Please enter your password (Optional)
set "user_pass="
for /f "delims=" %%p in ('powershell -ExecutionPolicy Bypass -NoProfile -Command "$securePass=Read-Host -AsSecureString -Prompt 'Password (ENTER for none)'; $bstr=[System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePass); $password=[System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr); [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr); $securePass.Dispose(); Write-Host $password"') do (
    set "user_pass=%%p"
)

set "ENCRYPT_FLAG=1"
if "!user_pass!"=="" (
    set "ENCRYPT_FLAG=0"
    echo.
    echo No password set. File will NOT be encrypted.
) else (
    echo.
    echo Password set. Please do not forget it.
)
echo.
:: === Password Section End ===

set "src_file=%~1"
set "src_name=%~nx1"
set "output_name_only=%~n1"
set "output_cmd=%~dp1%output_name_only%_decode.cmd"
set "temp_b64=%~dp1%~n1.b64"

echo ================== ENCODE PROCESS ==================
echo Source file    	: %src_name%
for %%F in ("%src_file%") do set "src_size=%%~zF"
if "%src_size%"=="" set "src_size=0"

if "%src_size%"=="0" (
    echo.
    echo ERROR: File not found or file size is 0 bytes.
    echo Checked path: "%src_file%"
    echo.
    echo If the filename contains spaces, ensure you use quotes in the command line:
    echo Example: %~n0 "My File.pdf"
    echo Or simply drag and drop the file onto the .bat file.
    echo.
    pause
    exit /b
)

set /a "size_mb=%src_size% / 1048576"
set /a "size_kb=(%src_size% %% 1048576) / 1024"
if %src_size% GEQ 1048576 (
    echo Source dimension: %size_mb%.%size_kb% MB ^(%src_size% bytes^)
) else (
    set /a "size_kb=%src_size% / 1024"
    echo Source dimension: %size_kb% KB ^(%src_size% bytes^)
)
for /f "delims=" %%H in ('certutil -hashfile "%src_file%" SHA256 ^| findstr /v "hash" ^| findstr /r /v "^$"') do set "src_sha=%%H"
echo Source SHA256  	: %src_sha%
echo.

:: === Optional Encryption Block ===
if "!ENCRYPT_FLAG!"=="1" (
    echo "Compressing, Encrypting (AES-256), and Encoding to Base64..."
    :: AES ENCRYPTED PATH 
    powershell -ExecutionPolicy Bypass -NoProfile -Command "$_m=[math]; $password='%user_pass%'; $sw=[Diagnostics.Stopwatch]::StartNew(); $file='%src_file%'; $out='%temp_b64%'; $bytes=[IO.File]::ReadAllBytes($file); $originalSize=$bytes.Length; Write-Host 'Original size    : ' -NoNewline; if($originalSize -ge 1MB){ Write-Host ('{0:F2} MB ({1} bytes)' -f ($originalSize/1MB),$originalSize) }else{ Write-Host ('{0:F2} KB ({1} bytes)' -f ($originalSize/1KB),$originalSize) }; $ms=[IO.MemoryStream]::new(); $gz=[IO.Compression.GZipStream]::new($ms,[IO.Compression.CompressionMode]::Compress); $gz.Write($bytes,0,$bytes.Length); $gz.Close(); $compressed=$ms.ToArray(); $ms.Close(); $bytes=0; $compressedSize=$compressed.Length; Write-Host 'Compressed size  : ' -NoNewline; if($compressedSize -ge 1MB){ Write-Host ('{0:F2} MB ({1} bytes)' -f ($compressedSize/1MB),$compressedSize) }else{ Write-Host ('{0:F2} KB ({1} bytes)' -f ($compressedSize/1KB),$compressedSize) }; $ratio=$_m::Round((1-($compressedSize/$originalSize))*100,1); Write-Host ('Compression      : {0}%%' -f $ratio); Write-Host ''; $salt=New-Object byte[] 16; (New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($salt); $iv=New-Object byte[] 16; (New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($iv); $kdf=New-Object System.Security.Cryptography.Rfc2898DeriveBytes($password, $salt, 10000); $key=$kdf.GetBytes(32); $aes=[System.Security.Cryptography.Aes]::Create(); $aes.Mode='CBC'; $aes.Padding='PKCS7'; $aes.Key=$key; $aes.IV=$iv; $encryptor=$aes.CreateEncryptor(); $msCrypt=[IO.MemoryStream]::new(); $cs=[System.Security.Cryptography.CryptoStream]::new($msCrypt, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write); $cs.Write($compressed, 0, $compressed.Length); $cs.FlushFinalBlock(); $cs.Close(); $encryptedData=$msCrypt.ToArray(); $msCrypt.Close(); $compressed=0; $aes.Clear(); Write-Host \"`rProgress: [\" ('='*30) \"] 100%%\"; $txtOut=[IO.StreamWriter]::new($out,[System.Text.Encoding]::Default); $txtOut.WriteLine('-----BEGIN CERTIFICATE-----'); $txtOut.Flush(); $b64Stream=[System.Security.Cryptography.CryptoStream]::new($txtOut.BaseStream,[System.Security.Cryptography.ToBase64Transform]::new(),[System.Security.Cryptography.CryptoStreamMode]::Write, $true); $b64Stream.Write($salt,0,$salt.Length); $b64Stream.Write($iv,0,$iv.Length); $b64Stream.Write($encryptedData,0,$encryptedData.Length); $b64Stream.FlushFinalBlock(); $b64Stream.Close(); $txtOut.WriteLine(); $txtOut.WriteLine('-----END CERTIFICATE-----'); $txtOut.Close(); $sw.Stop(); $ts=$sw.Elapsed; if($ts.TotalMinutes -ge 1){ Write-Host ('Time: {0} minute {1:F0} seconds' -f $_m::Floor($ts.TotalMinutes),$ts.Seconds) }else{ Write-Host ('Time: {0:F2} seconds' -f $ts.TotalSeconds) }"
) else (
    echo "Compressing and Encoding to Base64 (No Encryption)..."
    :: UNENCRYPTED PATH (GZip + Base64 Only)
    powershell -ExecutionPolicy Bypass -NoProfile -Command "$_m=[math]; $sw=[Diagnostics.Stopwatch]::StartNew(); $file='%src_file%'; $out='%temp_b64%'; $bytes=[IO.File]::ReadAllBytes($file); $originalSize=$bytes.Length; Write-Host 'Original size    : ' -NoNewline; if($originalSize -ge 1MB){ Write-Host ('{0:F2} MB ({1} bytes)' -f ($originalSize/1MB),$originalSize) }else{ Write-Host ('{0:F2} KB ({1} bytes)' -f ($originalSize/1KB),$originalSize) }; $ms=[IO.MemoryStream]::new(); $gz=[IO.Compression.GZipStream]::new($ms,[IO.Compression.CompressionMode]::Compress); $gz.Write($bytes,0,$bytes.Length); $gz.Close(); $compressed=$ms.ToArray(); $ms.Close(); $bytes=0; $compressedSize=$compressed.Length; Write-Host 'Compressed size  : ' -NoNewline; if($compressedSize -ge 1MB){ Write-Host ('{0:F2} MB ({1} bytes)' -f ($compressedSize/1MB),$compressedSize) }else{ Write-Host ('{0:F2} KB ({1} bytes)' -f ($compressedSize/1KB),$compressedSize) }; $ratio=$_m::Round((1-($compressedSize/$originalSize))*100,1); Write-Host ('Compression      : {0}%%' -f $ratio); Write-Host ''; Write-Host \"`rProgress: [\" ('='*30) \"] 100%%\"; $txtOut=[IO.StreamWriter]::new($out,[System.Text.Encoding]::Default); $txtOut.WriteLine('-----BEGIN CERTIFICATE-----'); $txtOut.Flush(); $b64Stream=[System.Security.Cryptography.CryptoStream]::new($txtOut.BaseStream,[System.Security.Cryptography.ToBase64Transform]::new(),[System.Security.Cryptography.CryptoStreamMode]::Write, $true); $b64Stream.Write($compressed,0,$compressed.Length); $b64Stream.FlushFinalBlock(); $b64Stream.Close(); $txtOut.WriteLine(); $txtOut.WriteLine('-----END CERTIFICATE-----'); $txtOut.Close(); $sw.Stop(); $ts=$sw.Elapsed; if($ts.TotalMinutes -ge 1){ Write-Host ('Time: {0} minute {1:F0} seconds' -f $_m::Floor($ts.TotalMinutes),$ts.Seconds) }else{ Write-Host ('Time: {0:F2} seconds' -f $ts.TotalSeconds) }"
)


for %%F in ("%temp_b64%") do set "b64_size=%%~zF"
set /a "b64_mb=%b64_size% / 1048576"
set /a "b64_kb=(%b64_size% %% 1048576) / 1024"
if %b64_size% GEQ 1048576 (
    echo B64 file size    : %b64_mb%.%b64_kb% MB ^(%b64_size% bytes^)
) else (
    set /a "b64_kb=%b64_size% / 1024"
    echo B64 file size    : %b64_kb% KB ^(%b64_size% bytes^)
)
echo ================== ENCODE PROCESS ==================

:: === Create Decoder Script ===
echo @echo off > "%output_cmd%"
echo title Base64 Decode by Abdullah ERTURK >> "%output_cmd%"
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
echo echo ================== DECODE PROCESS ================== >> "%output_cmd%"
echo echo Target file    : %%file%% >> "%output_cmd%"
echo echo. >> "%output_cmd%"
echo. >> "%output_cmd%"
echo powershell -ExecutionPolicy Bypass -NoProfile -Command "$_m=[math]; $ProgressPreference='SilentlyContinue'; $sw=[Diagnostics.Stopwatch]::StartNew(); $c=$false; $sb=[System.Text.StringBuilder]::new(2000000); $lines=@(Get-Content '%%~f0'); $t=$lines.Count; $i=0; $lp=-1; foreach($ln in $lines){ $i++; if($ln -eq '-----BEGIN CERTIFICATE-----'){ $c=$true; continue } if($ln -eq '-----END CERTIFICATE-----'){ $c=$false; break } if($c){ [void]$sb.Append($ln) } $pct=$_m::Floor(($i/$t)*100); if($pct -ne $lp -and ($pct %%%% 5) -eq 0){ $barLen=$_m::Min(30,$_m::Floor($pct/2)); $bar='='*$barLen; $space=' '*(30-$barLen); Write-Host `rProgress: [$bar$space] $pct%%%% -NoNewline; $lp=$pct } } Write-Host `rProgress: [ ('='*30) ] 100%%%%; try { $combinedData=[Convert]::FromBase64String($sb.ToString()); if($env:IS_ENCRYPTED -eq "1") { Write-Host 'This file is password protected.'; $securePass=Read-Host -Prompt 'Please enter password' -AsSecureString; $bstr=[System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePass); $password=[System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr); [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr); $securePass.Dispose(); $salt=New-Object byte[] 16; $iv=New-Object byte[] 16; $encryptedData=New-Object byte[] ($combinedData.Length - 32); [Array]::Copy($combinedData, 0, $salt, 0, 16); [Array]::Copy($combinedData, 16, $iv, 0, 16); [Array]::Copy($combinedData, 32, $encryptedData, 0, $encryptedData.Length); $kdf=New-Object System.Security.Cryptography.Rfc2898DeriveBytes($password, $salt, 10000); $key=$kdf.GetBytes(32); $aes=[System.Security.Cryptography.Aes]::Create(); $aes.Mode='CBC'; $aes.Padding='PKCS7'; $aes.Key=$key; $aes.IV=$iv; $decryptor=$aes.CreateDecryptor(); $msCrypt=[IO.MemoryStream]::new($encryptedData); $cs=[System.Security.Cryptography.CryptoStream]::new($msCrypt, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read); $msDecompressed=[IO.MemoryStream]::new(); $cs.CopyTo($msDecompressed); $compressed=$msDecompressed.ToArray(); $msCrypt.Close(); $cs.Close(); $msDecompressed.Close(); $aes.Clear(); } else { Write-Host 'File is not encrypted, decompressing...'; $compressed=$combinedData; } $ms=[IO.MemoryStream]::new($compressed); $gz=[IO.Compression.GZipStream]::new($ms,[IO.Compression.CompressionMode]::Decompress); $output=[IO.MemoryStream]::new(); $gz.CopyTo($output); $decompressed=$output.ToArray(); $gz.Close(); $ms.Close(); $output.Close(); [IO.File]::WriteAllBytes('%%file%%',$decompressed); $sw.Stop(); $ts=$sw.Elapsed; if($ts.TotalMinutes -ge 1){ Write-Host ('Time: {0} minute {1:F0} seconds' -f $_m::Floor($ts.TotalMinutes),$ts.Seconds) }else{ Write-Host ('Time: {0:F2} seconds' -f $ts.TotalSeconds) }; if(Test-Path '%%file%%'){ Write-Host 'SUCCESSFUL    : %%file%% created' } } catch [System.Security.Cryptography.CryptographicException] { Write-Host `nERROR: Wrong password or corrupted file. -ForegroundColor Red } catch { Write-Host `nUNEXPECTED ERROR: $_ -ForegroundColor Red }" >> "%output_cmd%"
echo. >> "%output_cmd%"
echo powershell -ExecutionPolicy Bypass -NoProfile -Command "if(Test-Path '%%file%%') { $sha = (Get-FileHash -Algorithm SHA256 '%%file%%').Hash; if($sha -eq '%src_sha%'){ Write-Host 'SHA256 VERIFIED: File integrity OK.' }else{ Write-Host 'SHA256 MISMATCH: File may be corrupted.' } }" >> "%output_cmd%"
echo. >> "%output_cmd%"
echo echo ================== DECODE PROCESS ================== >> "%output_cmd%"
echo echo. >> "%output_cmd%"
echo. >> "%output_cmd%"
echo pause >> "%output_cmd%"
echo goto :eof >> "%output_cmd%"

type "%temp_b64%" >> "%output_cmd%"
del "%temp_b64%"

echo.
echo Decode file: %output_cmd%
echo.
pause