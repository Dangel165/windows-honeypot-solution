using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SecurityToolkit.Tools
{
    public class EncryptionTool
    {
        public void EncryptFile(string inputPath, string outputPath, string password)
        {
            if (!File.Exists(inputPath))
            {
                Console.WriteLine("파일을 찾을 수 없습니다.");
                return;
            }

            try
            {
                byte[] salt = new byte[16];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(salt);
                }

                using (var key = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA256))
                using (var aes = Aes.Create())
                {
                    aes.Key = key.GetBytes(aes.KeySize / 8);
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    using (var fileStream = new FileStream(outputPath, FileMode.Create))
                    {
                        fileStream.Write(salt, 0, salt.Length);
                        fileStream.Write(aes.IV, 0, aes.IV.Length);

                        using (var encryptor = aes.CreateEncryptor())
                        using (var cryptoStream = new CryptoStream(fileStream, encryptor, CryptoStreamMode.Write))
                        using (var inputFile = File.OpenRead(inputPath))
                        {
                            inputFile.CopyTo(cryptoStream);
                        }
                    }

                    Console.WriteLine($"✓ 파일 암호화 완료: {outputPath}\n");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"오류: {ex.Message}");
            }
        }

        public void DecryptFile(string inputPath, string outputPath, string password)
        {
            if (!File.Exists(inputPath))
            {
                Console.WriteLine("파일을 찾을 수 없습니다.");
                return;
            }

            try
            {
                using (var fileStream = new FileStream(inputPath, FileMode.Open))
                {
                    byte[] salt = new byte[16];
                    fileStream.Read(salt, 0, salt.Length);

                    using (var key = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA256))
                    using (var aes = Aes.Create())
                    {
                        aes.Key = key.GetBytes(aes.KeySize / 8);
                        byte[] iv = new byte[aes.IV.Length];
                        fileStream.Read(iv, 0, iv.Length);
                        aes.IV = iv;
                        aes.Mode = CipherMode.CBC;
                        aes.Padding = PaddingMode.PKCS7;

                        using (var decryptor = aes.CreateDecryptor())
                        using (var cryptoStream = new CryptoStream(fileStream, decryptor, CryptoStreamMode.Read))
                        using (var outputFile = File.Create(outputPath))
                        {
                            cryptoStream.CopyTo(outputFile);
                        }
                    }

                    Console.WriteLine($"✓ 파일 복호화 완료: {outputPath}\n");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"오류: {ex.Message}");
            }
        }

        public void EncryptText(string plainText, string password)
        {
            try
            {
                byte[] salt = new byte[16];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(salt);
                }

                using (var key = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA256))
                using (var aes = Aes.Create())
                {
                    aes.Key = key.GetBytes(aes.KeySize / 8);
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    using (var encryptor = aes.CreateEncryptor())
                    {
                        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                        byte[] cipherBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
                        
                        byte[] result = new byte[salt.Length + aes.IV.Length + cipherBytes.Length];
                        Buffer.BlockCopy(salt, 0, result, 0, salt.Length);
                        Buffer.BlockCopy(aes.IV, 0, result, salt.Length, aes.IV.Length);
                        Buffer.BlockCopy(cipherBytes, 0, result, salt.Length + aes.IV.Length, cipherBytes.Length);

                        string encrypted = Convert.ToBase64String(result);
                        Console.WriteLine($"✓ 암호화된 텍스트:\n{encrypted}\n");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"오류: {ex.Message}");
            }
        }
    }
}
