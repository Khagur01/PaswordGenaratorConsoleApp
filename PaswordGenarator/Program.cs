using System.Security.Cryptography;
using System.Text;

namespace PasswordGeneratorApp;

/// <summary>
/// Kriptografik olarak güvenli rastgele şifre oluşturucu sınıf.
/// </summary>
public static class PasswordGenerator
{
    private const string UppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private const string LowercaseChars = "abcdefghijklmnopqrstuvwxyz";
    private const string DigitChars = "0123456789";
    private const string SpecialChars = "!@#$%^&*()_+-=[]{}|;:,.<>?";

    // Benzer karakterler
    private const string AmbiguousChars = "0O1lI|`'\"";

    // Yaygın zayıf kelimeler ve paternler
    private static readonly HashSet<string> CommonWeakWords = new(StringComparer.OrdinalIgnoreCase)
    {
        "password", "pass", "qwerty", "admin", "user", "login", "welcome",
        "letmein", "monkey", "dragon", "master", "sunshine", "princess",
        "football", "shadow", "michael", "jennifer", "computer", "123456",
        "password123", "admin123", "sifre", "parola", "kullanici", "giris"
    };

    public static string Generate(
        int length,
        bool includeUppercase,
        bool includeLowercase,
        bool includeDigits,
        bool includeSpecialChars,
        bool excludeAmbiguous = false)
    {
        if (length <= 0)
        {
            throw new ArgumentException("Şifre uzunluğu pozitif bir sayı olmalıdır.", nameof(length));
        }

        if (!includeUppercase && !includeLowercase && !includeDigits && !includeSpecialChars)
        {
            throw new ArgumentException("En az bir karakter tipi seçilmelidir.");
        }

        var charPool = new StringBuilder();
        var guaranteedChars = new StringBuilder();

        string uppercase = excludeAmbiguous ? RemoveAmbiguous(UppercaseChars) : UppercaseChars;
        string lowercase = excludeAmbiguous ? RemoveAmbiguous(LowercaseChars) : LowercaseChars;
        string digits = excludeAmbiguous ? RemoveAmbiguous(DigitChars) : DigitChars;
        string special = excludeAmbiguous ? RemoveAmbiguous(SpecialChars) : SpecialChars;

        if (includeUppercase)
        {
            charPool.Append(uppercase);
            guaranteedChars.Append(GetRandomChar(uppercase));
        }

        if (includeLowercase)
        {
            charPool.Append(lowercase);
            guaranteedChars.Append(GetRandomChar(lowercase));
        }

        if (includeDigits)
        {
            charPool.Append(digits);
            guaranteedChars.Append(GetRandomChar(digits));
        }

        if (includeSpecialChars)
        {
            charPool.Append(special);
            guaranteedChars.Append(GetRandomChar(special));
        }

        if (guaranteedChars.Length > length)
        {
            throw new ArgumentException(
                $"Şifre uzunluğu en az {guaranteedChars.Length} olmalıdır (seçilen karakter tipleri için).",
                nameof(length));
        }

        var password = new StringBuilder(guaranteedChars.ToString());
        string poolString = charPool.ToString();
        int remainingLength = length - guaranteedChars.Length;

        for (int i = 0; i < remainingLength; i++)
        {
            password.Append(GetRandomChar(poolString));
        }

        string result = Shuffle(password.ToString());

        // Yasaklı kelime kontrolü
        if (ContainsWeakPattern(result))
        {
            // Zayıf patern tespit edildi, yeniden oluştur
            return Generate(length, includeUppercase, includeLowercase, includeDigits, includeSpecialChars, excludeAmbiguous);
        }

        return result;
    }

    private static string RemoveAmbiguous(string input)
    {
        return new string(input.Where(c => !AmbiguousChars.Contains(c)).ToArray());
    }

    private static bool ContainsWeakPattern(string password)
    {
        string lower = password.ToLower();

        // Yaygın zayıf kelimeleri kontrol et
        foreach (var weakWord in CommonWeakWords)
        {
            if (lower.Contains(weakWord.ToLower()))
                return true;
        }

        // Ardışık karakterleri kontrol et (örn: "abc", "123", "qwe")
        int sequenceCount = 0;
        for (int i = 0; i < password.Length - 1; i++)
        {
            if (Math.Abs(password[i] - password[i + 1]) == 1)
            {
                sequenceCount++;
                if (sequenceCount >= 3) // 3 veya daha fazla ardışık karakter
                    return true;
            }
            else
            {
                sequenceCount = 0;
            }
        }

        return false;
    }

    private static char GetRandomChar(string chars)
    {
        if (string.IsNullOrEmpty(chars))
        {
            throw new ArgumentException("Karakter dizisi boş olamaz.", nameof(chars));
        }

        byte[] randomNumber = new byte[4];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(randomNumber);
        }

        uint randomValue = BitConverter.ToUInt32(randomNumber, 0);
        int index = (int)(randomValue % (uint)chars.Length);
        return chars[index];
    }

    private static string Shuffle(string input)
    {
        char[] array = input.ToCharArray();
        int n = array.Length;

        using (var rng = RandomNumberGenerator.Create())
        {
            byte[] randomBytes = new byte[4];

            for (int i = n - 1; i > 0; i--)
            {
                rng.GetBytes(randomBytes);
                int j = (BitConverter.ToInt32(randomBytes, 0) & int.MaxValue) % (i + 1);
                (array[i], array[j]) = (array[j], array[i]);
            }
        }

        return new string(array);
    }

    /// <summary>
    /// Şifrenin entropisini hesaplar (bit cinsinden).
    /// </summary>
    public static double CalculateEntropy(string password)
    {
        if (string.IsNullOrEmpty(password))
            return 0;

        int poolSize = 0;

        if (password.Any(char.IsUpper)) poolSize += 26;
        if (password.Any(char.IsLower)) poolSize += 26;
        if (password.Any(char.IsDigit)) poolSize += 10;
        if (password.Any(c => !char.IsLetterOrDigit(c))) poolSize += 32;

        return password.Length * Math.Log2(poolSize);
    }

    /// <summary>
    /// Şifre gücünü analiz eder.
    /// </summary>
    public static PasswordStrength AnalyzePassword(string password)
    {
        var strength = new PasswordStrength
        {
            Length = password.Length,
            HasUppercase = password.Any(char.IsUpper),
            HasLowercase = password.Any(char.IsLower),
            HasDigits = password.Any(char.IsDigit),
            HasSpecialChars = password.Any(c => !char.IsLetterOrDigit(c)),
            Entropy = CalculateEntropy(password),
            ContainsWeakPattern = ContainsWeakPattern(password)
        };

        // Güç puanı hesapla
        int score = 0;
        if (strength.HasUppercase) score++;
        if (strength.HasLowercase) score++;
        if (strength.HasDigits) score++;
        if (strength.HasSpecialChars) score++;
        if (strength.Length >= 12) score++;
        if (strength.Length >= 16) score++;
        if (strength.Entropy >= 60) score++;
        if (!strength.ContainsWeakPattern) score++;
        else score -= 2; // Zayıf patern varsa ceza

        strength.Score = Math.Max(0, score);

        // Seviye belirle
        if (strength.Score <= 2)
            strength.Level = "Çok Zayıf";
        else if (strength.Score <= 4)
            strength.Level = "Zayıf";
        else if (strength.Score <= 6)
            strength.Level = "Orta";
        else if (strength.Score <= 8)
            strength.Level = "Güçlü";
        else
            strength.Level = "Çok Güçlü";

        // Kırılma süresi tahmini (brute force için)
        strength.CrackTime = EstimateCrackTime(strength.Entropy);

        return strength;
    }

    private static string EstimateCrackTime(double entropy)
    {
        // 1 milyar deneme/saniye varsayımı (modern GPU)
        double combinations = Math.Pow(2, entropy);
        double seconds = combinations / 1_000_000_000;

        if (seconds < 1)
            return "Anında";
        if (seconds < 60)
            return $"{seconds:F0} saniye";
        if (seconds < 3600)
            return $"{seconds / 60:F0} dakika";
        if (seconds < 86400)
            return $"{seconds / 3600:F1} saat";
        if (seconds < 31536000)
            return $"{seconds / 86400:F0} gün";
        if (seconds < 31536000L * 100)
            return $"{seconds / 31536000:F0} yıl";

        return "Yüzyıllar";
    }
}

public class PasswordStrength
{
    public int Length { get; set; }
    public bool HasUppercase { get; set; }
    public bool HasLowercase { get; set; }
    public bool HasDigits { get; set; }
    public bool HasSpecialChars { get; set; }
    public double Entropy { get; set; }
    public bool ContainsWeakPattern { get; set; }
    public int Score { get; set; }
    public string Level { get; set; } = "";
    public string CrackTime { get; set; } = "";
}

// ============ KONSOL UYGULAMASI ============
class Program
{
    static void Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.Title = "Gelişmiş Şifre Oluşturucu";

        ShowHeader();

        while (true)
        {
            try
            {
                ShowMainMenu();
                string choice = Console.ReadLine()?.Trim() ?? "";

                switch (choice)
                {
                    case "1":
                        GenerateSinglePassword();
                        break;
                    case "2":
                        GenerateMultiplePasswords();
                        break;
                    case "3":
                        TestExistingPassword();
                        break;
                    case "4":
                        Console.ForegroundColor = ConsoleColor.Cyan;
                        Console.WriteLine("\n👋 Güvenli şifreler kullanın! Hoşça kalın.");
                        Console.ResetColor();
                        return;
                    default:
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("\n❌ Geçersiz seçim! Lütfen 1-4 arası bir sayı girin.");
                        Console.ResetColor();
                        break;
                }

                if (choice == "1" || choice == "2" || choice == "3")
                {
                    Console.WriteLine("\nDevam etmek için bir tuşa basın...");
                    Console.ReadKey();
                    Console.Clear();
                    ShowHeader();
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"\n❌ Hata: {ex.Message}");
                Console.ResetColor();
                Console.WriteLine("\nDevam etmek için bir tuşa basın...");
                Console.ReadKey();
                Console.Clear();
                ShowHeader();
            }
        }
    }

    static void ShowHeader()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("╔══════════════════════════════════════════════╗");
        Console.WriteLine("║   GELİŞMİŞ ŞİFRE OLUŞTURUCU v2.0            ║");
        Console.WriteLine("║   • Dictionary Attack Koruması               ║");
        Console.WriteLine("║   • Entropi Hesaplama                        ║");
        Console.WriteLine("║   • Benzer Karakter Filtreleme               ║");
        Console.WriteLine("╚══════════════════════════════════════════════╝");
        Console.ResetColor();
        Console.WriteLine();
    }

    static void ShowMainMenu()
    {
        Console.WriteLine("┌─────────────────────────────┐");
        Console.WriteLine("│       ANA MENÜ              │");
        Console.WriteLine("├─────────────────────────────┤");
        Console.WriteLine("│ 1. Tek Şifre Oluştur        │");
        Console.WriteLine("│ 2. Toplu Şifre Oluştur      │");
        Console.WriteLine("│ 3. Mevcut Şifreyi Test Et   │");
        Console.WriteLine("│ 4. Çıkış                    │");
        Console.WriteLine("└─────────────────────────────┘");
        Console.Write("\nSeçiminiz: ");
    }

    static void GenerateSinglePassword()
    {
        Console.WriteLine("\n═══ TEK ŞİFRE OLUŞTURMA ═══\n");

        int length = GetIntInput("Şifre uzunluğu (8-128): ", 8, 128);

        Console.WriteLine("\n--- Karakter Tipleri ---");
        bool includeUppercase = GetYesNoInput("Büyük harfler (A-Z)? (E/H): ");
        bool includeLowercase = GetYesNoInput("Küçük harfler (a-z)? (E/H): ");
        bool includeDigits = GetYesNoInput("Rakamlar (0-9)? (E/H): ");
        bool includeSpecialChars = GetYesNoInput("Özel karakterler (!@#$%...)? (E/H): ");
        bool excludeAmbiguous = GetYesNoInput("Benzer karakterleri hariç tut (0/O, 1/l/I)? (E/H): ");

        Console.WriteLine("\n⏳ Şifre oluşturuluyor...\n");
        string password = PasswordGenerator.Generate(
            length,
            includeUppercase,
            includeLowercase,
            includeDigits,
            includeSpecialChars,
            excludeAmbiguous);

        DisplayPassword(password);
    }

    static void GenerateMultiplePasswords()
    {
        Console.WriteLine("\n═══ TOPLU ŞİFRE OLUŞTURMA ═══\n");

        int count = GetIntInput("Kaç adet şifre oluşturulsun? (1-50): ", 1, 50);
        int length = GetIntInput("Şifre uzunluğu (8-128): ", 8, 128);

        Console.WriteLine("\n--- Karakter Tipleri ---");
        bool includeUppercase = GetYesNoInput("Büyük harfler (A-Z)? (E/H): ");
        bool includeLowercase = GetYesNoInput("Küçük harfler (a-z)? (E/H): ");
        bool includeDigits = GetYesNoInput("Rakamlar (0-9)? (E/H): ");
        bool includeSpecialChars = GetYesNoInput("Özel karakterler (!@#$%...)? (E/H): ");
        bool excludeAmbiguous = GetYesNoInput("Benzer karakterleri hariç tut? (E/H): ");

        Console.WriteLine($"\n⏳ {count} adet şifre oluşturuluyor...\n");

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("✓ Şifreler başarıyla oluşturuldu!");
        Console.ResetColor();
        Console.WriteLine(new string('═', 70));

        for (int i = 0; i < count; i++)
        {
            string password = PasswordGenerator.Generate(
                length,
                includeUppercase,
                includeLowercase,
                includeDigits,
                includeSpecialChars,
                excludeAmbiguous);

            var strength = PasswordGenerator.AnalyzePassword(password);

            Console.ForegroundColor = GetStrengthColor(strength.Level);
            Console.Write($"{i + 1,2}. ");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write($"{password,-40}");
            Console.ForegroundColor = GetStrengthColor(strength.Level);
            Console.WriteLine($" [{strength.Level}]");
            Console.ResetColor();
        }

        Console.WriteLine(new string('═', 70));
    }

    static void TestExistingPassword()
    {
        Console.WriteLine("\n═══ ŞİFRE TESTİ VE ANALİZİ ═══\n");
        Console.WriteLine("⚠️  Not: Şifreniz ekranda görünecektir.");
        Console.Write("\nTest edilecek şifreyi girin: ");
        string? password = Console.ReadLine();

        if (string.IsNullOrWhiteSpace(password))
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("\n❌ Boş şifre girilemez!");
            Console.ResetColor();
            return;
        }

        Console.WriteLine("\n⏳ Şifre analiz ediliyor...\n");
        DisplayPassword(password);
    }

    static void DisplayPassword(string password)
    {
        var strength = PasswordGenerator.AnalyzePassword(password);

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("✓ Analiz tamamlandı!");
        Console.ResetColor();
        Console.WriteLine(new string('═', 70));

        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"  ŞİFRE: {password}");
        Console.ResetColor();

        Console.WriteLine(new string('═', 70));

        Console.WriteLine("\n📊 DETAYLI ANALİZ:");
        Console.WriteLine(new string('─', 70));

        Console.Write("  Güç Seviyesi: ");
        Console.ForegroundColor = GetStrengthColor(strength.Level);
        Console.WriteLine($"{strength.Level} ({strength.Score}/10 puan)");
        Console.ResetColor();

        Console.WriteLine($"  Uzunluk: {strength.Length} karakter");
        Console.WriteLine($"  Entropi: {strength.Entropy:F2} bit");
        Console.WriteLine($"  Tahmini Kırılma Süresi: {strength.CrackTime}");

        Console.WriteLine("\n  Karakter İçeriği:");
        Console.WriteLine($"    ✓ Büyük Harf: {(strength.HasUppercase ? "Var" : "Yok")}");
        Console.WriteLine($"    ✓ Küçük Harf: {(strength.HasLowercase ? "Var" : "Yok")}");
        Console.WriteLine($"    ✓ Rakam: {(strength.HasDigits ? "Var" : "Yok")}");
        Console.WriteLine($"    ✓ Özel Karakter: {(strength.HasSpecialChars ? "Var" : "Yok")}");

        if (strength.ContainsWeakPattern)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("\n  ⚠️  UYARI: Zayıf patern veya yaygın kelime tespit edildi!");
            Console.ResetColor();
        }

        Console.WriteLine("\n💡 ÖNERİLER:");
        var suggestions = GetSuggestions(strength);
        if (suggestions.Count == 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  ✓ Şifreniz güvenli! Herhangi bir iyileştirme önerisi yok.");
            Console.ResetColor();
        }
        else
        {
            foreach (var suggestion in suggestions)
            {
                Console.WriteLine($"  • {suggestion}");
            }
        }

        Console.WriteLine(new string('═', 70));
    }

    static List<string> GetSuggestions(PasswordStrength strength)
    {
        var suggestions = new List<string>();

        if (strength.Length < 12)
            suggestions.Add("En az 12 karakter kullanın");
        if (!strength.HasUppercase)
            suggestions.Add("Büyük harf ekleyin");
        if (!strength.HasLowercase)
            suggestions.Add("Küçük harf ekleyin");
        if (!strength.HasDigits)
            suggestions.Add("Rakam ekleyin");
        if (!strength.HasSpecialChars)
            suggestions.Add("Özel karakter ekleyin");
        if (strength.ContainsWeakPattern)
            suggestions.Add("Yaygın kelimeler ve ardışık karakterlerden kaçının");
        if (strength.Entropy < 60)
            suggestions.Add("Daha karmaşık bir şifre oluşturun");

        return suggestions;
    }

    static ConsoleColor GetStrengthColor(string level)
    {
        return level switch
        {
            "Çok Zayıf" => ConsoleColor.DarkRed,
            "Zayıf" => ConsoleColor.Red,
            "Orta" => ConsoleColor.Yellow,
            "Güçlü" => ConsoleColor.Green,
            "Çok Güçlü" => ConsoleColor.Cyan,
            _ => ConsoleColor.White
        };
    }

    static int GetIntInput(string prompt, int min, int max)
    {
        while (true)
        {
            Console.Write(prompt);
            if (int.TryParse(Console.ReadLine(), out int value) && value >= min && value <= max)
            {
                return value;
            }
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"❌ Lütfen {min} ile {max} arasında bir sayı girin.");
            Console.ResetColor();
        }
    }

    static bool GetYesNoInput(string prompt)
    {
        while (true)
        {
            Console.Write(prompt);
            string input = Console.ReadLine()?.Trim().ToUpper() ?? "";

            if (input == "E" || input == "EVET")
                return true;
            if (input == "H" || input == "HAYIR")
                return false;

            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("❌ Lütfen 'E' (Evet) veya 'H' (Hayır) girin.");
            Console.ResetColor();
        }
    }
}

