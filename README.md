Gelişmiş Şifre Oluşturucu (Advanced Password Generator)
Bu proje, C# ve .NET 8+ kullanılarak geliştirilmiş, kriptografik olarak güvenli şifreler üreten ve mevcut şifrelerin gücünü analiz eden gelişmiş bir konsol uygulamasıdır.

Uygulama, standart System.Random yerine, tahmin edilmesi çok daha zor olan System.Security.Cryptography.RandomNumberGenerator sınıfını kullanarak yüksek güvenlikli ve rastgele şifreler oluşturur.

🚀 Temel Özellikler
Kriptografik Güvenlik: RandomNumberGenerator ile oluşturulan, yüksek entropiye sahip güvenli şifreler.

Şifre Oluşturma:

Belirtilen kriterlere göre (uzunluk, karakter tipi) tekli şifre oluşturma.

Belirtilen kriterlere göre toplu şifre listesi oluşturma.

Gelişmiş Şifre Analizi:

Mevcut bir şifrenin gücünü test etme.

Entropi Hesaplama: Şifrenin karmaşıklığını bit cinsinden hesaplar.

Tahmini Kırılma Süresi: Modern bir GPU'nun (saniyede 1 Milyar deneme varsayımıyla) şifreyi kaba kuvvet (brute-force) ile kırmasının ne kadar süreceğini tahmin eder.

Zayıf Patern Koruması (Dictionary Attack Koruması):

"password", "123456", "admin" gibi yaygın ve zayıf kelimeleri içeren şifreleri tespit eder ve engeller.

"abc" veya "987" gibi ardışık karakter dizilerini tespit eder.

Kullanıcı Dostu Seçenekler:

Büyük harf (A-Z)

Küçük harf (a-z)

Rakam (0-9)

Özel karakterler (!@#$...)

Benzer Karakter Filtreleme: Okunabilirliği artırmak için 0 (sıfır) ile O (harf) veya 1 (bir) ile l (harf) gibi benzer karakterleri (0O1lI|) hariç tutma seçeneği.

🖥️ Uygulama Görüntüsü (Demo)
Uygulamanın ana menüsü:

Shell

╔══════════════════════════════════════════════╗
║   GELİŞMİŞ ŞİFRE OLUŞTURUCU v2.0             ║
║   • Dictionary Attack Koruması               ║
║   • Entropi Hesaplama                        ║
║   • Benzer Karakter Filtreleme               ║
╚══════════════════════════════════════════════╝

┌─────────────────────────────┐
│       ANA MENÜ              │
├─────────────────────────────┤
│ 1. Tek Şifre Oluştur        │
│ 2. Toplu Şifre Oluştur      │
│ 3. Mevcut Şifreyi Test Et   │
│ 4. Çıkış                    │
└─────────────────────────────┘

Seçiminiz: 1
Şifre oluşturma ve analiz ekranı:

Shell

═══ TEK ŞİFRE OLUŞTURMA ═══

Şifre uzunluğu (8-128): 20

--- Karakter Tipleri ---
Büyük harfler (A-Z)? (E/H): e
Küçük harfler (a-z)? (E/H): e
Rakamlar (0-9)? (E/H): e
Özel karakterler (!@#$%...)? (E/H): e
Benzer karakterleri hariç tut (0/O, 1/l/I)? (E/H): e

⏳ Şifre oluşturuluyor...

✓ Analiz tamamlandı!
══════════════════════════════════════════════════════════════════════
  ŞİFRE: Fp(g+2k*R!Jb_9w}q7y
══════════════════════════════════════════════════════════════════════

📊 DETAYLI ANALİZ:
──────────────────────────────────────────────────────────────────────
  Güç Seviyesi: Çok Güçlü (10/10 puan)
  Uzunluk: 20 karakter
  Entropi: 125.75 bit
  Tahmini Kırılma Süresi: Yüzyıllar

  Karakter İçeriği:
     ✓ Büyük Harf: Var
     ✓ Küçük Harf: Var
     ✓ Rakam: Var
     ✓ Özel Karakter: Var

💡 ÖNERİLER:
  ✓ Şifreniz güvenli! Herhangi bir iyileştirme önerisi yok.
══════════════════════════════════════════════════════════════════════

Devam etmek için bir tuşa basın...
🛠️ Gereksinimler
.NET 8.0 SDK (veya daha yenisi)

⚙️ Nasıl Çalıştırılır?
Bu repoyu klonlayın veya ZIP olarak indirin:

Bash

git clone https://github.com/[KULLANICI_ADINIZ]/[PROJE_ADINIZ].git
Proje dizinine gidin:

Bash

cd [PROJE_ADINIZ]
Uygulamayı çalıştırın:

Bash

dotnet run
