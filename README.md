<a href="https://buymeacoffee.com/abdullaherturk" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 60px !important;width: 217px !important;" ></a>

# SecureEncode 
**SecureEncode (AES-256 Encrypted)**

![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge)
![Tech](https://img.shields.io/badge/Tech-Batch_&_PowerShell-blue?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-AES--256_|_GZip-red?style=for-the-badge)

[![made-for-windows](https://img.shields.io/badge/Made%20for-Windows-00A4E3.svg?style=flat&logo=microsoft)](https://www.microsoft.com/)
[![Open Source?](https://img.shields.io/badge/Open%20source%3F-Of%20course%21%20%E2%9D%A4-009e0a.svg?style=flat)](https://github.com/abdullah-erturk/Secure-Encode)

![sample](https://github.com/abdullah-erturk/Secure-Encode/blob/main/preview.gif)
**Ön izleme gif resmi eski versiyona ait / The preview gif image is from the old version**

Herhangi bir dosyayı isteğe bağlı **AES-256 parola koruması** ile kendi kendini açabilen `.cmd` arşivine dönüştüren bir Windows Batch betiği.

A Windows Batch script that converts **any file** into a single, self-extracting `.cmd` archive, with optional **AES-256 password protection**.

---

<details>
<summary><strong>Türkçe Tanıtım</strong></summary>

---

# SecureEncode (AES-256 Encrypt & Decrypt)

## Proje Hakkında

Bu proje, bir dosyayı alıp, onu kendi kendini çözebilen (self-extracting) tek bir Windows komut dosyasına (.cmd) dönüştüren bir "Kodlayıcı" (Encoder) betiğidir.

Oluşturulan bu `.cmd` dosyası, orijinal dosyanızı içinde (isteğe bağlı olarak) **AES-256 ile şifrelenmiş** veya **şifrelenmemiş (RAW) binary** olarak barındırır. Bu `.cmd` dosyasını herhangi bir Windows 7, 8.1, 10, 11 ve veya Server işletim sisteminde çalıştırdığınızda, (eğer parola korumalıysa) sizden şifreyi ister ve orijinal dosyayı güvenli bir şekilde kurtarır.

## ✨ Özellikler

* **Betik Bütünlük Koruması:** Ana `SecureEncode.bat` betiği, çalıştırılmadan önce kendi dosya bütünlüğünü (SHA256) kontrol eder. Eğer betik değiştirilmiş veya bozulmuşsa, güvenlik nedeniyle çalışmayı durdurur.
* **Sağ Tık Menüsü Entegrasyonu:** Betiğe çift tıklayarak, "Dosyayı Şifrele (Güvenli Kodlama AES-256)" seçeneğini (kilit simgesiyle birlikte) Windows sağ tık menüsüne ekleyen/kaldıran bir kurulum sihirbazı çalışır.
* **Kendi Kendini Çözen (Self-Extracting):** Veriyi ve veriyi çözen mantığı tek bir `.cmd` dosyasında birleştirir.
* **İsteğe Bağlı AES-256 Şifreleme:** Dosyanızı parola ile koruma seçeneği sunar.
    * **Parola girilirse:** Dosya, **AES-256**, **PBKDF2** (10.000 iterasyon) ve rastgele **Salt/IV** kullanılarak şifrelenir.
    * **Parola girilmezse (Enter'a basılırsa):** Dosya **şifrelenmez**. Sadece ham (RAW) binary olarak paketlenir.
* **Parola Doğrulama (Sentinel):** Kod çözücü betik, şifreyi girdiğiniz anda (tüm dosyayı çözmeyi beklemeden) parolanın doğru olup olmadığını anında doğrular. Bu, 'magic bytes' (sentinel) kontrolü ile yapılır ve yanlış şifrede zaman kaybını veya bozulmayı önler.
* **Sistem Dizin Koruması:** `C:\Windows`, `C:\Program Files` ve `C:\` ana dizini gibi kritik sistem klasörlerindeki dosyaların yanlışlıkla şifrelenmesini engeller.
* **Verimli Akış (Streaming):** Yüksek boyutlu dosyaları (örn. 300MB+) `OutOfMemoryException` (Bellek Yetersiz) hatası vermeden işler. Komut dosyası, veriyi Base64 olarak değil, doğrudan ham binary olarak kendi içine ekler ve çözerken de akış (stream) yöntemini kullanır.
* **Güvenli Şifre Girişi:** Hem kodlayıcı hem de çözücü betiklerde şifre girişi `***` karakterleri ile gizlenir.
* **SHA256 Bütünlük Kontrolü:** Kod çözücü betik, dosyayı kurtardıktan sonra orijinal dosyanın SHA256 hash değerini kontrol ederek verinin bozulup bozulmadığını doğrular.
* **Unicode Dosya Adı Desteği:** Orijinal dosya adı (özel karakterler ve Unicode dahil) kod çözücü betiğin içinde Base64 olarak saklanır ve kurtarılır.
* **Salt Okunur Çıktı:** Oluşturulan `_decode.cmd` dosyası, yanlışlıkla düzenlenmeyi önlemek için 'Salt Okunur' olarak ayarlanır.
* **Geniş Uyumluluk:** Windows 7, 8.1, 10, 11 ve Server üzerinde tam uyumlu çalışır.
* **Bağımsızlık:** Harici bir yazılıma ihtiyaç duymaz, sadece Windows'un kendi Batch ve PowerShell (v2.0+) motorlarını kullanır.

## 🚀 Nasıl Kullanılır?

### Yükleme (Önerilen Yöntem)

1.  Bu repodan `SecureEncode.bat` betiğini indirin.
2.  Betiğe **çift tıklayın**.
3.  Yönetici (UAC) izni istendiğinde "Evet" deyin.
4.  Kurulum menüsü göründüğünde, **E** (Evet) tuşuna basın.
5.  Kurulum tamamlandığında, betik herhangi bir dosyaya sağ tıkladığınızda menüde (kilit simgesiyle) görünecektir.

### 1. Encode (Dosyayı Paketleme)

**Yöntem 1: Sağ Tık ile (Kurulum Gerekli)**
1.  Paketlemek istediğiniz herhangi bir dosyaya **sağ tıklayın**.
2.  **Dosyayı Şifrele (Güvenli Kodlama AES-256)** seçeneğine tıklayın.

**Yöntem 2: Sürükle-Bırak (Kurulum Gerekmez)**
1.  Paketlemek istediğiniz herhangi bir dosyayı (örn: `MySecretFile.zip`) `SecureEncode.bat` dosyasının üzerine **sürükleyip bırakın**.

**İki yöntem için de ortak adımlar:**
1.  Bir komut istemi açılacaktır. Güçlü bir şifre belirleyin ve **Enter**'a basın. (Şifresiz, sadece ham binary olarak paketlemek için **Enter**'a basıp geçin.)
2.  İşlem tamamlandığında, aynı klasörde `MySecretFile_decode.cmd` adında yeni bir dosya oluşacaktır.

### 2. Decode (Dosyayı Kurtarma)

1.  Oluşturduğunuz `..._decode.cmd` dosyasını alın ve (e-posta, USB vb. ile) hedef makineye taşıyın.
2.  Dosyaya **çift tıklayarak** çalıştırın.
3.  Eğer şifrelediyseniz, komut istemi sizden şifreyi (yine `***` olarak gizli) isteyecektir. Doğru şifreyi girin.
4.  Betik, orijinal dosyayı (örn: `MySecretFile.zip`) aynı klasöre kurtaracak ve dosya bütünlüğünü doğrulayacaktır.

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

**Özet: Hassas veriler için ASLA zayıf şifreler kullanmayın.**

## ⚙️ Bağımlılıklar

* Windows 7, 8.1, 10, 11 veya Server
* PowerShell 5.0 veya üzeri (Tüm Windows 10 ve üzeri sistemlerde varsayılan olarak bulunur)
* Windows 7 and 8.1 için indirme linki: : [Windows Management Framework 5.1](https://www.microsoft.com/en-us/download/details.aspx?id=54616)

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

This project is an "Encoder" script that takes any file and converts it into a single, **self-extracting** Windows command script (.cmd).

This generated `.cmd` file contains your original file, either (optionally) **AES-256 encrypted** or as **raw, unencrypted binary data**. When you run this `.cmd` file on any Windows 7, 8.1, 10, 11 or Server OS, it will (if password-protected) prompt you for the password and securely recover the original file.

## ✨ Features

* **Script Integrity Protection:** The main `SecureEncode.bat` script verifies its own file integrity (SHA256) before running. If the script has been modified or corrupted, it will stop execution for security.
* **Right-Click Menu Integration:** Double-clicking the script runs an installation wizard that adds/removes an "Encrypt File (SecureEncode AES-256)" option (complete with a **lock icon**) to the Windows right-click menu.
* **Self-Extracting:** Combines the data and the extraction logic into a single `.cmd` file.
* **Optional AES-256 Encryption:** Provides the option to protect your file with a password.
    * **If a password is provided:** The file is encrypted using **AES-256**, **PBKDF2** (10,000 iterations), and a random **Salt/IV**.
    * **If no password is provided (Enter is pressed):** The file is **not encrypted**. It is only packed as raw binary data.
* **Password Verification (Sentinel):** The decoder script instantly verifies if the password is correct upon entry, *before* decrypting the entire file. This is done using a 'magic bytes' sentinel check, preventing wasted time or corruption on a wrong password.
* **System Directory Protection:** Prevents accidental encryption of files in critical system folders like `C:\Windows`, `C:\Program Files`, and the `C:\` root directory.
* **Efficient Streaming:** Handles massive files (e.g., 300MB+) without `OutOfMemoryException`. The script appends the raw binary data (not Base64) to itself and uses a stream-based method for extraction.
* **Secure Password Input:** Password entry is masked with `***` characters in both the encoder and decoder scripts.
* **SHA256 Integrity Check:** After extraction, the decoder script verifies the SHA256 hash of the recovered file against the original hash to ensure the data is not corrupted.
* **Unicode Filename Support:** The original filename (including special characters and Unicode) is preserved by storing it as Base64 within the decoder script.
* **Read-Only Output:** The generated `_decode.cmd` file is set to 'Read-Only' to prevent accidental editing.
* **Wide Compatibility:** Fully compatible with Windows 7, 8.1, 10, 11, and Server.
* **No Dependencies:** Requires no external software, using only native Windows Batch and PowerShell (v2.0+).

## 🚀 How to Use?

### Installation (Recommended Method)

1.  Download the `SecureEncode.bat` script from this repository.
2.  **Double-click** the script.
3.  Say "Yes" to the Administrator (UAC) prompt.
4.  When the installation menu appears, press **Y** (Yes).
5.  Once complete, the script will appear in the right-click menu (with a lock icon) for any file.

### 1. Encode (Packing the File)

**Method 1: Right-Click (Requires Installation)**
1.  **Right-click** on any file you want to pack.
2.  Click the **Encrypt File (SecureEncode AES-256)** option.

**Method 2: Drag-and-Drop (No Installation Needed)**
1.  **Drag** your file (e.g., `MySecretFile.zip`) and **drop** it onto the `SecureEncode.bat` script file.

**Common Steps for Both Methods:**
1.  A command prompt will open. Set a strong password and press **Enter**. (Press **ENTER** to skip for unencrypted, raw binary packing.)
2.  Once finished, a new file named `MySecretFile_decode.cmd` will be created in the same folder.

### 2. Decode (Recovering the File)

1.  Take your generated `..._decode.cmd` file and move it to the target machine (via email, USB, etc.).
2.  **Double-click** the file to run it.
3.  If you encrypted it, the command prompt will ask for the password (again, masked with `***`). Enter the correct password.
4.  The script will recover the original file (e.g., `MySecretFile.zip`) in the same folder and verify its integrity.

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

**Summary: NEVER use weak passwords for sensitive data.**

## ⚙️ Dependencies

* Windows 7, 8.1, 10, 11, or Server
* PowerShell 5.0 or later (Included by default on all Windows 10 and later systems)
* Download link for Windows 7 and 8.1: [Windows Management Framework 5.1](https://www.microsoft.com/en-us/download/details.aspx?id=54616)

## Author
**Abdullah ERTÜRK**
* [https://github.com/abdullah-erturk](https://github.com/abdullah-erturk)
* [https://erturk.netlify.app](https://erturk.netlify.app)
</details>
