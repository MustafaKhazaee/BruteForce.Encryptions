
using System.Text;
using System.Security.Cryptography;

namespace BruteForce.Encryptions;

public class AESEncryption
{
    private const string _allowedCharacters = "012[';34567$%89ABCDEF&*()_GHIJKLMNrstOPQR67UVWXYZ~`!@#^+|,}{]:,>=-abcdefghijkmnopqS[;:Tuvw4589~`!@#$%^&*()_+|xyz0123}{]',>=-";

    public static async Task<string> EncryptAsync(string plainText, string key, byte[] iv)
    {
        ArgumentException.ThrowIfNullOrEmpty(plainText);
        byte[] encrypted;
        using var aes = Aes.Create();
        aes.Mode = CipherMode.CFB;
        aes.Padding = PaddingMode.PKCS7;
        aes.FeedbackSize = 128;
        aes.Key = Encoding.UTF8.GetBytes(key);
        aes.IV = iv;
        var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
        using var msEncrypt = new MemoryStream();
        using var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
        using var swEncrypt = new StreamWriter(csEncrypt);
        await swEncrypt.WriteAsync(plainText);
        encrypted = msEncrypt.ToArray();
        return Convert.ToBase64String(encrypted);
    }

    public static async Task<string> DecryptAsync(string cipherText, string key, byte[] iv)
    {
        ArgumentException.ThrowIfNullOrEmpty(cipherText);
        var cipherTextBytes = Convert.FromBase64String(cipherText);
        using var aes = Aes.Create();
        aes.Mode = CipherMode.CFB;
        aes.Padding = PaddingMode.PKCS7;
        aes.FeedbackSize = 128;
        aes.Key = Encoding.UTF8.GetBytes(key);
        aes.IV = iv;
        var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
        using var msDecrypt = new MemoryStream(cipherTextBytes);
        using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
        using var srDecrypt = new StreamReader(csDecrypt);
        return await srDecrypt.ReadToEndAsync();
    }

    public static string GenerateRandomSecret()
    {
        Random rd = new();

        char[] chars = new char[24];

        for (int i = 0; i < 24; i++)
        {
            var t = rd.Next(0, _allowedCharacters.Length);
            chars[i] = _allowedCharacters[t];
        }

        return new string(chars);
    }

    public static byte[] GenerateRandomInitializationVector() => RandomNumberGenerator.GetBytes(16);
}