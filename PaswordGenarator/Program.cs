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

    /// <summary>
    /// Belirtilen kriterlere göre güvenli bir şifre oluşturur.
    /// </summary>
    public static string Generate(
        int length,
        bool includeUppercase,
        bool includeLowercase,
        bool includeDigits,
        bool includeSpecialChars)
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

        if (includeUppercase)
        {
            charPool.Append(UppercaseChars);
            guaranteedChars.Append(GetRandomChar(UppercaseChars));
        }

        if (includeLowercase)
        {
            charPool.Append(LowercaseChars);
            guaranteedChars.Append(GetRandomChar(LowercaseChars));
        }

        if (includeDigits)
        {
            charPool.Append(DigitChars);
            guaranteedChars.Append(GetRandomChar(DigitChars));
        }

        if (includeSpecialChars)
        {
            charPool.Append(SpecialChars);
            guaranteedChars.Append(GetRandomChar(SpecialChars));
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

        return Shuffle(password.ToString());
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

        int index = BitConverter.ToInt32(randomNumber, 0) & int.MaxValue;
        return chars[index % chars.Length];
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
}

// ============ KONSOL UYGULAMASI ============
class Program
{
    static void Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.Title = "Güvenli Şifre Oluşturucu";

        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("╔════════════════════════════════════════╗");
        Console.WriteLine("║   GÜVENLİ ŞİFRE OLUŞTURUCU v1.0       ║");
        Console.WriteLine("╚════════════════════════════════════════╝");
        Console.ResetColor();
        Console.WriteLine();

        while (true)
        {
            try
            {
                // Şifre uzunluğu
                int length = GetIntInput("Şifre uzunluğu (8-128): ", 8, 128);

                // Karakter seçenekleri
                Console.WriteLine("\n--- Karakter Tipleri ---");
                bool includeUppercase = GetYesNoInput("Büyük harfler (A-Z) dahil edilsin mi? (E/H): ");
                bool includeLowercase = GetYesNoInput("Küçük harfler (a-z) dahil edilsin mi? (E/H): ");
                bool includeDigits = GetYesNoInput("Rakamlar (0-9) dahil edilsin mi? (E/H): ");
                bool includeSpecialChars = GetYesNoInput("Özel karakterler (!@#$%...) dahil edilsin mi? (E/H): ");

                // Şifre oluştur
                Console.WriteLine("\n⏳ Şifre oluşturuluyor...\n");
                string password = PasswordGenerator.Generate(
                    length,
                    includeUppercase,
                    includeLowercase,
                    includeDigits,
                    includeSpecialChars);

                // Sonucu göster
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("✓ Şifreniz başarıyla oluşturuldu!");
                Console.ResetColor();
                Console.WriteLine(new string('─', 50));
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"  {password}");
                Console.ResetColor();
                Console.WriteLine(new string('─', 50));

                // Şifre gücü analizi
                ShowPasswordStrength(password, length);

                // Devam etme seçeneği
                Console.WriteLine();
                if (!GetYesNoInput("Yeni bir şifre oluşturmak ister misiniz? (E/H): "))
                {
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine("\n👋 Güvenli şifreler kullanın! Hoşça kalın.");
                    Console.ResetColor();
                    break;
                }

                Console.Clear();
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("╔════════════════════════════════════════╗");
                Console.WriteLine("║   GÜVENLİ ŞİFRE OLUŞTURUCU v1.0       ║");
                Console.WriteLine("╚════════════════════════════════════════╝");
                Console.ResetColor();
                Console.WriteLine();
            }
            catch (ArgumentException ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"\n❌ Hata: {ex.Message}");
                Console.ResetColor();
                Console.WriteLine("\nLütfen tekrar deneyin...\n");
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"\n❌ Beklenmeyen hata: {ex.Message}");
                Console.ResetColor();
                break;
            }
        }
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

    static void ShowPasswordStrength(string password, int length)
    {
        int strength = 0;

        if (password.Any(char.IsUpper)) strength++;
        if (password.Any(char.IsLower)) strength++;
        if (password.Any(char.IsDigit)) strength++;
        if (password.Any(c => !char.IsLetterOrDigit(c))) strength++;
        if (length >= 12) strength++;
        if (length >= 16) strength++;

        Console.WriteLine("\n📊 Şifre Gücü Analizi:");

        string strengthText;
        ConsoleColor strengthColor;

        if (strength <= 2)
        {
            strengthText = "Zayıf";
            strengthColor = ConsoleColor.Red;
        }
        else if (strength <= 4)
        {
            strengthText = "Orta";
            strengthColor = ConsoleColor.Yellow;
        }
        else
        {
            strengthText = "Güçlü";
            strengthColor = ConsoleColor.Green;
        }

        Console.Write("  Güç Seviyesi: ");
        Console.ForegroundColor = strengthColor;
        Console.WriteLine($"{strengthText} ({strength}/6)");
        Console.ResetColor();

        Console.WriteLine($"  Uzunluk: {length} karakter");
        Console.WriteLine($"  Karakter Çeşitliliği: {strength - (length >= 12 ? 1 : 0) - (length >= 16 ? 1 : 0)}/4");
    }
}
