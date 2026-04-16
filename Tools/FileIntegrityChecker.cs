using System;
using System.IO;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Linq;

namespace SecurityToolkit.Tools
{
    public class FileIntegrityChecker
    {
        private Dictionary<string, string> fileHashes = new();

        public void CalculateHash(string filePath)
        {
            if (!File.Exists(filePath))
            {
                Console.WriteLine($"파일을 찾을 수 없습니다: {filePath}");
                return;
            }

            try
            {
                using (var sha256 = SHA256.Create())
                using (var stream = File.OpenRead(filePath))
                {
                    byte[] hash = sha256.ComputeHash(stream);
                    string hashString = BitConverter.ToString(hash).Replace("-", "").ToLower();
                    fileHashes[filePath] = hashString;
                    Console.WriteLine($"✓ 파일: {Path.GetFileName(filePath)}");
                    Console.WriteLine($"  SHA256: {hashString}\n");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"오류: {ex.Message}");
            }
        }

        public void VerifyIntegrity(string filePath)
        {
            if (!fileHashes.ContainsKey(filePath))
            {
                Console.WriteLine("이 파일의 해시값이 저장되어 있지 않습니다.");
                return;
            }

            try
            {
                using (var sha256 = SHA256.Create())
                using (var stream = File.OpenRead(filePath))
                {
                    byte[] hash = sha256.ComputeHash(stream);
                    string hashString = BitConverter.ToString(hash).Replace("-", "").ToLower();
                    
                    if (hashString == fileHashes[filePath])
                    {
                        Console.WriteLine("✓ 파일 무결성 확인됨 - 변조되지 않았습니다.\n");
                    }
                    else
                    {
                        Console.WriteLine("✗ 경고: 파일이 변조되었습니다!\n");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"오류: {ex.Message}");
            }
        }

        public void MonitorDirectory(string directoryPath)
        {
            if (!Directory.Exists(directoryPath))
            {
                Console.WriteLine("디렉토리를 찾을 수 없습니다.");
                return;
            }

            var files = Directory.GetFiles(directoryPath);
            Console.WriteLine($"디렉토리 모니터링: {directoryPath}");
            Console.WriteLine($"총 {files.Length}개 파일 검사 중...\n");

            foreach (var file in files)
            {
                CalculateHash(file);
            }
        }
    }
}
