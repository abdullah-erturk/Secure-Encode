<a href="https://buymeacoffee.com/abdullaherturk" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 60px !important;width: 217px !important;" ></a>
  
# SecureEncrypt v5
**SecureEncrypt (AES-256 Encrypt & Decrypt)**

![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge)
![Tech](https://img.shields.io/badge/Tech-Batch_&_PowerShell-blue?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-AES--256_|_XOR_Obfuscation-red?style=for-the-badge)

[![made-for-windows](https://img.shields.io/badge/Made%20for-Windows-00A4E3.svg?style=flat&logo=microsoft)](https://www.microsoft.com/)
[![Open Source?](https://img.shields.io/badge/Open%20source%3F-Of%20course%21%20%E2%9D%A4-009e0a.svg?style=flat)](https://github.com/abdullah-erturk/Secure-Encode)

![sample](https://github.com/abdullah-erturk/Secure-Encode/blob/main/preview.gif)

**Ön izleme gif resmi eski versiyona ait / The preview gif image is from the old version**

Dosya ve klasörleri isteğe bağlı **AES-256 parola koruması** ile kendi kendini açabilen `.cmd` arşivine dönüştüren bir Windows Batch betiği.

A Windows Batch script that converts **files and folders** into a single, self-extracting `.cmd` archive, with optional **AES-256 password protection**.

---

<details>
<summary><strong>Türkçe Tanıtım</strong></summary>

---

# SecureEncrypt (AES-256 Encrypt & Decrypt)

## Proje Hakkında

Bu proje, bir dosyayı veya **klasörü** alıp, onu kendi kendini çözebilen (self-extracting) tek bir Windows komut dosyasına (.cmd) dönüştüren bir "Şifreleme" (Encrypt) betiğidir.

Oluşturulan bu `.cmd` dosyası, orijinal dosyanızı veya klasörünüzü içinde (isteğe bağlı olarak) **AES-256 ile şifrelenmiş** veya **şifrelenmemiş (RAW) binary** olarak barındırır. Bu `.cmd` dosyasını herhangi bir Windows 7, 8.1, 10, 11 ve veya Server işletim sisteminde çalıştırdığınızda, (eğer parola korumalıysa) sizden şifreyi ister ve orijinal dosyayı/klasörü güvenli bir şekilde kurtarır.

## ✨ Özellikler

* **Betik Bütünlük Koruması:** Ana `SecureEncrypt.cmd` betiği, çalıştırılmadan önce kendi dosya bütünlüğünü (SHA256) kontrol eder. Eğer betik değiştirilmiş veya bozulmuşsa, güvenlik nedeniyle çalışmayı durdurur ve beklenen hash değerini gösterir.
* **Sağ Tık Menüsü Entegrasyonu:** Betiğe çift tıklayarak, hem dosyalar hem de klasörler için "Dosyayı/Klasörü Şifrele (Secure Encrypt AES-256)" seçeneğini (kilit simgesiyle birlikte) Windows sağ tık menüsüne ekleyen/kaldıran bir kurulum sihirbazı çalışır.
* **Klasör Desteği:** Tüm içeriğiyle birlikte klasörleri şifreleyebilir. Klasörler otomatik olarak ZIP arşivine dönüştürülür, şifrelenir ve çözüldükten sonra otomatik olarak aynı yapıda geri yüklenir.
* **Boş Klasör Koruması:** Boş klasörlerin şifrelenmesini engelleyerek hata oluşmasını önler.
* **Kendi Kendini Çözen (Self-Extracting):** Veriyi ve veriyi çözen mantığı tek bir `.cmd` dosyasında birleştirir.
* **İsteğe Bağlı AES-256 Şifreleme:** Dosyanızı/klasörünüzü parola ile koruma seçeneği sunar.
    * **Parola girilirse:** İçerik, **AES-256**, **PBKDF2** (10.000 iterasyon) ve rastgele **Salt/IV** kullanılarak şifrelenir.
    * **Parola girilmezse (Enter'a basılırsa):** İçerik **şifrelenmez**. Sadece ham (RAW) binary olarak paketlenir.
* **Akıllı Metin Dosyası Gizleme (XOR Obfuscation):** Şifre kullanılmadığında, metin dosyaları (txt, bat, cmd, vbs, ps1, log, csv, json, xml, html, css, js vb.) için otomatik olarak XOR tabanlı basit bir gizleme (obfuscation) uygulanır. Bu, metin içeriğinin doğrudan okunmasını zorlaştırır ancak güçlü şifreleme yerine geçmez.
* **Parola Doğrulama (Sentinel):** Kod çözücü betik, şifreyi girdiğiniz anda (tüm dosyayı çözmeyi beklemeden) parolanın doğru olup olmadığını anında doğrular. Bu, 'magic bytes' (sentinel) kontrolü ile yapılır ve yanlış şifrede zaman kaybını veya bozulmayı önler.
* **Gelişmiş Sistem Dizin Koruması:** `C:\Windows`, `C:\Program Files`, `$Recycle.Bin`, `System Volume Information` ve `C:\` ana dizini gibi kritik sistem klasörlerindeki dosyaların/klasörlerin yanlışlıkla şifrelenmesini engeller. Sadece kullanıcı profili (`%USERPROFILE%`) altındaki konumlar güvenli kabul edilir.
* **Çoklu Dosya Koruması:** Aynı anda birden fazla dosya/klasör sürüklendiğinde uyarı verir ve işlemi engeller.
* **Verimli Akış (Streaming):** Yüksek boyutlu dosyaları (örn. 300MB+) `OutOfMemoryException` (Bellek Yetersiz) hatası vermeden işler. İlerleme çubuğu ile işlem durumunu gösterir.
* **Güvenli Şifre Girişi:** Hem kodlayıcı hem de çözücü betiklerde şifre girişi `***` karakterleri ile gizlenir ve bellekten güvenli bir şekilde temizlenir.
* **SHA256 Bütünlük Kontrolü:** Kod çözücü betik, dosyayı kurtardıktan sonra orijinal dosyanın SHA256 hash değerini kontrol ederek verinin bozulup bozulmadığını doğrular.
* **Unicode Dosya Adı Desteği:** Orijinal dosya/klasör adı (özel karakterler ve Unicode dahil) kod çözücü betiğin içinde Base64 olarak saklanır ve kurtarılır.
* **Salt Okunur Çıktı:** Hem ana betik hem de oluşturulan `_decrypt.cmd` dosyası, yanlışlıkla düzenlenmeyi önlemek için 'Salt Okunur' olarak ayarlanır.
* **PowerShell Versiyon Uyumluluğu:** PowerShell 5+ sistemlerde optimize edilmiş `Compress-Archive` kullanırken, eski sistemlerde (Win7/8.1) Legacy VBScript tabanlı ZIP yöntemi ile uyumlu çalışır.
* **Otomatik Klasör Çıkarma:** Şifrelenmiş klasörler, çözüldükten sonra PowerShell veya Shell.Application ile otomatik olarak orijinal yapılarında çıkarılır ve ZIP dosyası temizlenir.
* **Geniş Uyumluluk:** Windows 7, 8.1, 10, 11 ve Server üzerinde tam uyumlu çalışır.
* **Bağımsızlık:** Harici bir yazılıma ihtiyaç duymaz, sadece Windows'un kendi Batch ve PowerShell (v2.0+) motorlarını kullanır.

## 🚀 Nasıl Kullanılır?

### Yükleme (Önerilen Yöntem)

1.  Bu repodan `SecureEncrypt.cmd` betiğini indirin.
2.  Betiğe **çift tıklayın**.
3.  Yönetici (UAC) izni istendiğinde "Evet" deyin.
4.  Kurulum menüsü göründüğünde, **E** (Evet) tuşuna basın.
5.  Kurulum tamamlandığında, betik herhangi bir dosya veya klasöre sağ tıkladığınızda menüde (kilit simgesiyle) görünecektir.
6.  **Kaldırma:** Betiği tekrar çalıştırın ve "Kaldırmak istiyor musunuz?" sorusunda **E** tuşuna basın.

### 1. Encrypt (Dosya/Klasör Şifreleme)

**Yöntem 1: Sağ Tık ile (Kurulum Gerekli)**
1.  Şifrelemek istediğiniz herhangi bir **dosya** veya **klasöre** **sağ tıklayın**.
2.  **Encrypt File/Folder (Secure Encrypt AES-256)** seçeneğine tıklayın.

**Yöntem 2: Sürükle-Bırak (Kurulum Gerekmez)**
1.  Şifrelemek istediğiniz herhangi bir dosyayı/klasörü (örn: `MyFolder` veya `MySecretFile.zip`) `SecureEncrypt.cmd` dosyasının üzerine **sürükleyip bırakın**.

**İki yöntem için de ortak adımlar:**
1.  Bir komut istemi açılacaktır. Güçlü bir şifre belirleyin ve **Enter**'a basın. (Şifresiz, sadece ham binary olarak paketlemek için **Enter**'a basıp geçin.)
2.  İşlem sırasında ilerleme çubuğu ve detaylı bilgiler gösterilir.
3.  İşlem tamamlandığında, aynı klasörde `MyFolder_decrypt.cmd` veya `MySecretFile_decrypt.cmd` adında yeni bir dosya oluşacaktır.

**Önemli Notlar:**
- Klasörler şifrelenirken otomatik olarak ZIP arşivine çevrilir
- Boş klasörler şifrelenemez
- Sistem klasörleri (`C:\Windows`, `C:\Program Files` vb.) korunur
- Şifre kullanılmazsa metin dosyaları XOR ile gizlenir (binary dosyalar olduğu gibi kalır)

### 2. Decrypt (Dosya/Klasör Kurtarma)

1.  Oluşturduğunuz `..._decrypt.cmd` dosyasını alın ve (e-posta, USB vb. ile) hedef makineye taşıyın.
2.  Dosyaya **çift tıklayarak** çalıştırın.
3.  Eğer şifrelediyseniz, komut istemi sizden şifreyi (yine `***` olarak gizli) isteyecektir. Doğru şifreyi girin.
4.  Betik, orijinal dosyayı/klasörü (örn: `MyFolder` veya `MySecretFile.zip`) aynı klasöre kurtaracak ve dosya bütünlüğünü doğrulayacaktır.
5.  Eğer bir klasör şifrelendiyse, ZIP otomatik olarak çıkarılır ve klasör yapısı geri yüklenir.

## 🔒 Güvenlik Modeli: Şifrem Kırılabilir mi?

Bu betiğin güvenliği, sizin seçtiğiniz parolanın gücüne **%100 bağlıdır**.

* **Algoritma (AES-256): Kırılamaz.** Bu, bankacılık ve askeri sistemlerde kullanılan endüstri standardıdır. Bir saldırganın şifrenizi bilmeden veriyi çözmesi matematiksel olarak imkansızdır.
* **Şifreniz (Sizin Sorumluluğunuz): Kırılabilir.** Bir saldırgan, algoritmayı kırmayı denemez; sizin şifrenizi *tahmin etmeyi* (Brute-Force / Kaba Kuvvet) dener.

| Şifre Gücü | Örnek Şifre | Kırılma Süresi (Tahmini) | Güvenlik Durumu |
| :--- | :--- | :--- | :--- |
| Çok Zayıf | `1` veya `123` | Saniyeler | **GÜVENSİZ** |
| Zayıf | `password123` | Dakikalar / Saatler | **GÜVENSİZ** |
| Güçlü | `Benim!Sifrem-1990` | Yüzyıllar | **GÜVENLİ** |
| Paranoyak | `kirmizi-araba-77-hizli-gider?` | Trilyonlarca Yıl | **KIRILAMAZ** |

**XOR Obfuscation Notu:** Şifre kullanılmadan paketlenen metin dosyaları için uygulanan XOR gizleme, **gerçek bir şifreleme değildir**. Sadece içeriğin düz metin olarak görünmesini engeller. Hassas veriler için mutlaka güçlü bir parola kullanın!

**Özet: Hassas veriler için ASLA zayıf şifreler kullanmayın.**

## ⚙️ Bağımlılıklar

* Windows 7, 8.1, 10, 11 veya Server (.NetFrameWork v4.5 gerekli - Windows 7 ve 8.1 için)
* PowerShell 2.0 veya üzeri (Tüm Windows 7 ve üzeri sistemlerde varsayılan olarak bulunur)
* Windows 7/8.1 sistemlerde klasör şifreleme için PowerShell 2.0 ve Shell.Application COM desteği

## 📝 Teknik Detaylar

### Şifreleme Özellikleri
- **Algoritma:** AES-256-CBC
- **Anahtar Türetme:** PBKDF2 (RFC2898) - 10,000 iterasyon
- **Salt:** 16 byte rastgele
- **IV:** 16 byte rastgele
- **Padding:** PKCS7
- **Bütünlük:** SHA256 hash kontrolü
- **Sentinel:** 32-byte magic bytes (`__SECURE_ENCODE_MAGIC_BYTES_OK__`) ile anında parola doğrulama

### Klasör İşleme
- PowerShell 5+: `Compress-Archive` ile optimize edilmiş sıkıştırma
- PowerShell 2.0-4.x: VBScript Shell.Application ile legacy ZIP desteği
- Çıkarma: PowerShell Expand-Archive veya Shell.Application COM
- Otomatik ZIP temizleme

### XOR Obfuscation (Metin Dosyaları)
- Anahtar: `default_xor_key_for_text_obfuscation_secure_encrypt`
- Otomatik metin/binary algılama (null byte kontrolü)
- Akış tabanlı işleme (bellek verimliliği)

## 🛡️ Güvenlik Özellikleri

1. **Betik İmzası Kontrolü:** SHA256 hash doğrulama ile değişiklik tespiti
2. **Sistem Koruması:** Kritik dizinlerde otomatik engelleme
3. **Çoklu Dosya Koruması:** Tek seferde bir dosya/klasör işlemi
4. **Güvenli Bellek Yönetimi:** Şifrelerin bellekten temizlenmesi
5. **Salt Okunur:** Yanlışlıkla düzenlemeye karşı koruma
6. **Hata Yönetimi:** Kapsamlı try-catch blokları ve kullanıcı dostu hata mesajları

## Yazar
**Abdullah ERTÜRK**
* [https://github.com/abdullah-erturk](https://github.com/abdullah-erturk)
* [https://erturk.netlify.app](https://erturk.netlify.app)

</details>

---

<details>
<summary><strong>English Description</strong></summary>

---

## About the Project

This project is an "Encrypt" script that takes any file or **folder** and converts it into a single, **self-extracting** Windows command script (.cmd).

This generated `.cmd` file contains your original file or folder, either (optionally) **AES-256 encrypted** or as **raw, unencrypted binary data**. When you run this `.cmd` file on any Windows 7, 8.1, 10, 11 or Server OS, it will (if password-protected) prompt you for the password and securely recover the original file/folder.

## ✨ Features

* **Script Integrity Protection:** The main `SecureEncrypt.cmd` script verifies its own file integrity (SHA256) before running. If the script has been modified or corrupted, it will stop execution for security and display the expected hash value.
* **Right-Click Menu Integration:** Double-clicking the script runs an installation wizard that adds/removes an "Encrypt File/Folder (Secure Encrypt AES-256)" option (complete with a **lock icon**) to the Windows right-click menu for both files and folders.
* **Folder Support:** Can encrypt entire folders with all their contents. Folders are automatically converted to ZIP archives, encrypted, and automatically restored to their original structure after decryption.
* **Empty Folder Protection:** Prevents encryption of empty folders to avoid errors.
* **Self-Extracting:** Combines the data and the extraction logic into a single `.cmd` file.
* **Optional AES-256 Encryption:** Provides the option to protect your file/folder with a password.
    * **If a password is provided:** Content is encrypted using **AES-256**, **PBKDF2** (10,000 iterations), and a random **Salt/IV**.
    * **If no password is provided (Enter is pressed):** Content is **not encrypted**. It is only packed as raw binary data.
* **Smart Text File Obfuscation (XOR):** When no password is used, text files (txt, bat, cmd, vbs, ps1, log, csv, json, xml, html, css, js, etc.) are automatically obfuscated using simple XOR-based encoding. This makes the text content harder to read directly but is not strong encryption.
* **Password Verification (Sentinel):** The decoder script instantly verifies if the password is correct upon entry, *before* decrypting the entire file. This is done using a 'magic bytes' sentinel check, preventing wasted time or corruption on a wrong password.
* **Advanced System Directory Protection:** Prevents accidental encryption of files/folders in critical system folders like `C:\Windows`, `C:\Program Files`, `$Recycle.Bin`, `System Volume Information`, and the `C:\` root directory. Only locations under the user profile (`%USERPROFILE%`) are considered safe.
* **Multiple File Protection:** Warns and blocks the operation if multiple files/folders are dragged at once.
* **Efficient Streaming:** Handles massive files (e.g., 300MB+) without `OutOfMemoryException`. Shows progress bar during operations.
* **Secure Password Input:** Password entry is masked with `***` characters in both the encoder and decoder scripts and securely cleared from memory.
* **SHA256 Integrity Check:** After extraction, the decoder script verifies the SHA256 hash of the recovered file against the original hash to ensure the data is not corrupted.
* **Unicode Filename Support:** The original file/folder name (including special characters and Unicode) is preserved by storing it as Base64 within the decoder script.
* **Read-Only Output:** Both the main script and the generated `_decrypt.cmd` file are set to 'Read-Only' to prevent accidental editing.
* **PowerShell Version Compatibility:** Uses optimized `Compress-Archive` on PowerShell 5+ systems, while maintaining compatibility with legacy systems (Win7/8.1) using VBScript-based ZIP method.
* **Automatic Folder Extraction:** Encrypted folders are automatically extracted to their original structure using PowerShell or Shell.Application after decryption, and the ZIP file is cleaned up.
* **Wide Compatibility:** Fully compatible with Windows 7, 8.1, 10, 11, and Server.
* **No Dependencies:** Requires no external software, using only native Windows Batch and PowerShell (v2.0+).

## 🚀 How to Use?

### Installation (Recommended Method)

1.  Download the `SecureEncrypt.cmd` script from this repository.
2.  **Double-click** the script.
3.  Say "Yes" to the Administrator (UAC) prompt.
4.  When the installation menu appears, press **Y** (Yes).
5.  Once complete, the script will appear in the right-click menu (with a lock icon) for any file or folder.
6.  **Uninstall:** Run the script again and answer **Y** to "Do you want to uninstall it?"

### 1. Encrypt (File/Folder Encryption)

**Method 1: Right-Click (Requires Installation)**
1.  **Right-click** on any **file** or **folder** you want to encrypt.
2.  Click the **Encrypt File/Folder (Secure Encrypt AES-256)** option.

**Method 2: Drag-and-Drop (No Installation Needed)**
1.  **Drag** your file/folder (e.g., `MyFolder` or `MySecretFile.zip`) and **drop** it onto the `SecureEncrypt.cmd` script file.

**Common Steps for Both Methods:**
1.  A command prompt will open. Set a strong password and press **Enter**. (Press **ENTER** to skip for unencrypted, raw binary packing.)
2.  Progress bars and detailed information will be displayed during the operation.
3.  Once finished, a new file named `MyFolder_decrypt.cmd` or `MySecretFile_decrypt.cmd` will be created in the same folder.

**Important Notes:**
- Folders are automatically converted to ZIP archives during encryption
- Empty folders cannot be encrypted
- System folders (`C:\Windows`, `C:\Program Files`, etc.) are protected
- Without a password, text files are XOR-obfuscated (binary files remain as-is)

### 2. Decrypt (File/Folder Recovery)

1.  Take your generated `..._decrypt.cmd` file and move it to the target machine (via email, USB, etc.).
2.  **Double-click** the file to run it.
3.  If you encrypted it, the command prompt will ask for the password (again, masked with `***`). Enter the correct password.
4.  The script will recover the original file/folder (e.g., `MyFolder` or `MySecretFile.zip`) in the same folder and verify its integrity.
5.  If a folder was encrypted, the ZIP is automatically extracted and the folder structure is restored.

## 🔒 Security Model: Can My Password Be Broken?

The security of this script is **100% dependent on the strength of your chosen password**.

* **The Algorithm (AES-256): Unbreakable.** This is the industry standard used in banking and military systems. It is mathematically impossible for an attacker to decrypt the data without knowing your password.
* **Your Password (Your Responsibility): Breakable.** An attacker will not try to break the algorithm; they will try to *guess* your password (Brute-Force).

| Password Strength | Example Password | Time to Crack (Approx.) | Security Status |
| :--- | :--- | :--- | :--- |
| Very Weak | `1` or `123` | Seconds | **INSECURE** |
| Weak | `password123` | Minutes / Hours | **INSECURE** |
| Strong | `My!Pass-1990` | Centuries | **SECURE** |
| Paranoid | `red-car-77-fast-goes?` | Trillions of Years | **UNBREAKABLE** |

**XOR Obfuscation Note:** The XOR obfuscation applied to text files when no password is used is **not real encryption**. It only prevents the content from being viewed as plain text. Always use a strong password for sensitive data!

**Summary: NEVER use weak passwords for sensitive data.**

## ⚙️ Dependencies

* Windows 7, 8.1, 10, 11, or Server (.NetFrameWork v4.5 required for Windows 7 and 8.1)
* PowerShell 2.0 or later (Included by default on all Windows 7 and later systems)
* PowerShell 2.0 and Shell.Application COM support for folder encryption on Windows 7/8.1 systems

## 📝 Technical Details

### Encryption Features
- **Algorithm:** AES-256-CBC
- **Key Derivation:** PBKDF2 (RFC2898) - 10,000 iterations
- **Salt:** 16-byte random
- **IV:** 16-byte random
- **Padding:** PKCS7
- **Integrity:** SHA256 hash verification
- **Sentinel:** 32-byte magic bytes (`__SECURE_ENCODE_MAGIC_BYTES_OK__`) for instant password verification

### Folder Processing
- PowerShell 5+: Optimized compression with `Compress-Archive`
- PowerShell 2.0-4.x: Legacy ZIP support via VBScript Shell.Application
- Extraction: PowerShell Expand-Archive or Shell.Application COM
- Automatic ZIP cleanup

### XOR Obfuscation (Text Files)
- Key: `default_xor_key_for_text_obfuscation_secure_encrypt`
- Automatic text/binary detection (null byte check)
- Stream-based processing (memory efficient)

## 🛡️ Security Features

1. **Script Signature Check:** SHA256 hash verification to detect modifications
2. **System Protection:** Automatic blocking in critical directories
3. **Multiple File Protection:** Single file/folder operation at a time
4. **Secure Memory Management:** Password clearing from memory
5. **Read-Only:** Protection against accidental editing
6. **Error Handling:** Comprehensive try-catch blocks and user-friendly error messages

## Author
**Abdullah ERTÜRK**
* [https://github.com/abdullah-erturk](https://github.com/abdullah-erturk)
* [https://erturk.netlify.app](https://erturk.netlify.app)

</details>

