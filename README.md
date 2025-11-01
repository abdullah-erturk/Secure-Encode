<a href="https://buymeacoffee.com/abdullaherturk" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 60px !important;width: 217px !important;" ></a>

# SecureEncode 
**Base64 Encrypt & Decrypt (AES-256 Encrypted)**

![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge)
![Tech](https://img.shields.io/badge/Tech-Batch_&_PowerShell-blue?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-AES--256_|_GZip-red?style=for-the-badge)

[![made-for-windows](https://img.shields.io/badge/Made%20for-Windows-00A4E3.svg?style=flat&logo=microsoft)](https://www.microsoft.com/)
[![Open Source?](https://img.shields.io/badge/Open%20source%3F-Of%20course%21%20%E2%9D%A4-009e0a.svg?style=flat)](https://github.com/abdullah-erturk/Secure-Encode)

![sample](https://github.com/abdullah-erturk/Secure-Encode/blob/main/preview.gif)

Herhangi bir dosyayı isteğe bağlı **AES-256 parola koruması** ve **GZip sıkıştırması** ile kendi kendini açabilen `.cmd` arşivine dönüştüren bir Windows Batch betiği.

A Windows Batch script that converts **any file** into a single, self-extracting `.cmd` archive, with optional **AES-256 password protection** and **GZip compression**.

---

<details>
<summary><strong>Türkçe Tanıtım</strong></summary>

## Proje Hakkında

Bu proje, bir dosyayı (`.zip`, `.pdf`, `.exe`, `.txt` veya `.iso` vb. olabilir) alıp, onu **kendi kendini çözebilen (self-extracting)** tek bir Windows komut dosyasına (`.cmd`) dönüştüren bir "Kodlayıcı" (Encoder) betiğidir.

Oluşturulan bu `.cmd` dosyası, orijinal dosyanızı GZip ile sıkıştırılmış ve (isteğe bağlı olarak) AES-256 ile şifrelenmiş halde içinde barındırır. Bu `.cmd` dosyasını herhangi bir Windows 7, 8.1, 10 veya 11 işletim sisteminde çalıştırdığınızda, sizden şifreyi ister ve orijinal dosyayı
güvenli bir şekilde kurtarır.


## Özellikler

* **Kendi Kendini Çözen (Self-Extracting):** Veriyi ve veriyi çözen mantığı tek bir `.cmd` dosyasında birleştirir.
* **İsteğe Bağlı AES-256 Şifreleme:** Dosyanızı parola ile koruma seçeneği sunar.
    * Parola girilirse: Dosya, **AES-256**, **PBKDF2 (10.000 iterasyon)** ve rastgele **Salt/IV** kullanılarak şifrelenir.
    * Parola girilmezse (Enter'a basılırsa): Dosya şifrelenmez, sadece sıkıştırılır.
* **GZip Sıkıştırma:** Şifrelensin veya şifrelenmesin, tüm dosyalar GZip ile sıkıştırılarak son dosya boyutu küçültülür.
* **Büyük Dosya Desteği:** Yüksek boyutlu dosyaları (örn. 300MB+ dosyaları) `OutOfMemoryException` (Bellek Yetersiz) hatası vermeden işler. Base64 dönüşümü RAM yerine doğrudan dosyaya "akıtılır" (stream).
* **Güvenli Şifre Girişi:** Hem kodlayıcı hem de çözücü betiklerde şifre girişi `***` karakterleri ile gizlenir.
* **SHA256 Bütünlük Kontrolü:** Çözücü betik, dosyayı kurtardıktan sonra orijinal dosyanın SHA256 hash değerini kontrol ederek verinin bozulup bozulmadığını doğrular.
* **Geniş Uyumluluk:** **Windows 7, 8.1, 10,11 ve Server** üzerinde tam uyumlu çalışır.
* **Bağımsızlık:** Harici bir yazılıma ihtiyaç duymaz, sadece Windows'un kendi Batch ve PowerShell (v2.0+) motorlarını kullanır.

## Nasıl Kullanılır?

İşlem iki adımdan oluşur: KODLAMA ve ÇÖZME.

   ### 1. Encode (Dosyayı Paketleme)

1.  Bu repodan `SecureEncode.bat` betiğini indirin.
2.  Paketlemek istediğiniz herhangi bir dosyayı (örn: `MySecretFile.zip`) `SecureEncode.bat` dosyasının üzerine **sürükleyip bırakın**.
3.  Bir komut istemi açılacaktır. Güçlü bir şifre belirleyin ve `Enter`'a basın.
    * *(Şifresiz paketlemek için `Enter`'a basıp geçin.)*
4.  İşlem tamamlandığında, aynı klasörde `MySecretFile_decode.cmd` adında yeni bir dosya oluşacaktır.

   ### 2. Decode (Dosyayı Kurtarma)

1.  Oluşturduğunuz `..._decode.cmd` dosyasını alın ve (e-posta, USB vb. ile) hedef makineye taşıyın.
2.  Dosyaya çift tıklayarak çalıştırın.
3.  Eğer şifrelediyseniz, komut istemi sizden şifreyi (yine `***` olarak gizli) isteyecektir. Doğru şifreyi girin.
4.  Betik, orijinal dosyayı (`MySecretFile.zip`) aynı klasöre kurtaracak ve dosya bütünlüğünü doğrulayacaktır.

   ## Güvenlik Modeli: Şifrem Kırılabilir mi?

Bu betiğin güvenliği, sizin seçtiğiniz parolanın gücüne **%100 bağlıdır**.

* **Algoritma (AES-256):** Kırılamaz. Bu, bankacılık ve askeri sistemlerde kullanılan endüstri standardıdır. Bir saldırganın şifrenizi bilmeden veriyi çözmesi matematiksel olarak imkansızdır.
* **Şifreniz (Sizin Sorumluluğunuz):** Kırılabilir. Bir saldırgan, algoritmayı kırmayı denemez; sizin şifrenizi *tahmin etmeyi* (Brute-Force / Kaba Kuvvet) dener.

#### Güvenlik Seviyeleri:

| Şifre Gücü | Örnek Şifre | Kırılma Süresi (Tahmini) | Güvenlik Durumu |
| :--- | :--- | :--- | :--- |
| **Çok Zayıf** | `1` veya `123` | Saniyeler | **GÜVENSİZ** |
| **Zayıf** | `password123` | Dakikalar / Saatler | **GÜVENSİZ** |
| **Güçlü** | `Benim!Sifrem-1990` | Yüzyıllar | **GÜVENLİ** |
| **Parola** | `kirmizi-araba-77-hizli-gider?` | Trilyonlarca Yıl | **KIRILAMAZ** |

**Özet: Hassas veriler için ASLA zayıf şifreler kullanmayın.**

## Bağımlılıklar

* Windows 7, 8.1, 10, 11 veya Server
* PowerShell 2.0 veya üzeri (Tüm Windows 7 ve üzeri sistemlerde varsayılan olarak bulunur)

## Yazar

**Abdullah ERTÜRK**
* [https://github.com/abdullah-erturk](https://github.com/abdullah-erturk)
* [https://erturk.netlify.app](https://erturk.netlify.app)

</details>

---

<details>
<summary><strong>English Description</strong></summary>

---

## About The Project

This project is an "Encoder" script that takes any file (`.zip`, `.pdf`, `.exe`, `.txt` or `.iso` etc.) and converts it into a single, **self-extracting** Windows command script (`.cmd`).

This generated `.cmd` file contains your original file, compressed with GZip and (optionally) encrypted with AES-256. When you run this `.cmd` file on any Windows 7, 8.1, 10, or 11 operatin system, it will prompt you for the password and securely recover the original file.

## Features

* **Self-Extracting:** Combines the data and the logic to decode it into a single `.cmd` file.
* **Optional AES-256 Encryption:** Provides the option to protect your file with a password.
    * If a password is provided: The file is encrypted using **AES-256**, **PBKDF2 (10,000 iterations)**, and a random **Salt/IV**.
    * If no password is provided (Enter is pressed): The file is not encrypted, only compressed.
* **GZip Compression:** Whether encrypted or not, all files are compressed with GZip to reduce the final file size.
* **Large File Support:** Processes large files (e.g., 300MB+ files) without throwing an `OutOfMemoryException`. The Base64 conversion is "streamed" directly to the file instead of being held in RAM.
* **Secure Password Entry:** Password entry is masked with `***` characters in both the encoder and decoder scripts.
* **SHA256 Integrity Check:** After recovering the file, the decoder script verifies the SHA256 hash of the original file to confirm the data was not corrupted.
* **Wide Compatibility:** Fully compatible with **Windows 7, 8.1, 10, 11 and Server**.
* **Zero Dependencies:** Requires no external software, using only Windows' native Batch and PowerShell (v2.0+) engines.

## How to Use

The process consists of two steps: ENCODING and DECODING.

   ### 1. Encode (Packing the File)

1.  Download the `SecureEncode.bat` script from this repo.
2.  **Drag and drop** any file you want to pack (e.g., `MySecretFile.zip`) onto the `SecureEncode.bat` file.
3.  A command prompt will open. Set a strong password and press `Enter`.
    * *(To pack without a password, just press `Enter`.)*
4.  When the process is complete, a new file named `MySecretFile_decode.cmd` will be created in the same folder.

   ### 2. Decode (Recovering the File)

1.  Take the generated `..._decode.cmd` file and move it to the target machine (via email, USB, etc.).
2.  Double-click the file to run it.
3.  If you encrypted it, the command prompt will ask for the password (again, masked with `***`). Enter the correct password.
4.  The script will recover the original file (`MySecretFile.zip`) in the same folder and verify its integrity.

   ## Security Model: Can My Password Be Cracked?

The security of this script is **100% dependent on the strength of the password you choose**.

* **The Algorithm (AES-256):** Unbreakable. This is the industry standard used in banking and military systems. It is mathematically impossible for an attacker to decode the data without knowing your password.
* **Your Password (Your Responsibility):** Crackable. An attacker will not try to break the algorithm; they will try to *guess* your password (known as a Brute-Force or Dictionary Attack).

#### Security Levels:

| Password Strength | Example Password | Time to Crack (Estimate) | Security Status |
| :--- | :--- | :--- | :--- |
| **Very Weak** | `1` or `123` | Seconds | **INSECURE** |
| **Weak** | `password123` | Minutes / Hours | **INSECURE** |
| **Strong** | `My!Passw-1990` | Centuries | **SECURE** |
| **Passphrase** | `red-car-77-goes-fast?` | Trillions of Years | **UNBREAKABLE** |

**Summary: NEVER use weak passwords for sensitive data.**

## Dependencies

* Windows 7, 8.1, 10, 11 or Server
* PowerShell 2.0 or higher (Installed by default on all Windows 7 systems and newer)

## Author

**Abdullah ERTÜRK**
* [https://github.com/abdullah-erturk](https://github.com/abdullah-erturk)
* [https://erturk.netlify.app](https://erturk.netlify.app)
</details>
