using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Collections.Generic;

namespace SecurityToolkit.Tools
{
    public class FilePermissionMonitor
    {
        public void CheckFilePermissions(string filePath)
        {
            if (!File.Exists(filePath))
            {
                Console.WriteLine("파일을 찾을 수 없습니다.");
                return;
            }

            try
            {
                var fileInfo = new FileInfo(filePath);
                var fileSecurity = fileInfo.GetAccessControl();
                var rules = fileSecurity.GetAccessRules(true, true, typeof(NTAccount));

                Console.WriteLine($"파일: {Path.GetFileName(filePath)}");
                Console.WriteLine($"경로: {filePath}");
                Console.WriteLine($"크기: {FormatFileSize(fileInfo.Length)}");
                Console.WriteLine($"생성: {fileInfo.CreationTime:yyyy-MM-dd HH:mm:ss}");
                Console.WriteLine($"수정: {fileInfo.LastWriteTime:yyyy-MM-dd HH:mm:ss}\n");

                Console.WriteLine("=== 접근 권한 ===\n");
                foreach (FileSystemAccessRule rule in rules)
                {
                    Console.WriteLine($"사용자: {rule.IdentityReference}");
                    Console.WriteLine($"권한: {rule.FileSystemRights}");
                    Console.WriteLine($"유형: {rule.AccessControlType}");
                    Console.WriteLine();
                }

                CheckRiskFactors(fileSecurity);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"오류: {ex.Message}");
            }
        }

        public void CheckDirectoryPermissions(string directoryPath)
        {
            if (!Directory.Exists(directoryPath))
            {
                Console.WriteLine("디렉토리를 찾을 수 없습니다.");
                return;
            }

            try
            {
                var dirInfo = new DirectoryInfo(directoryPath);
                var dirSecurity = dirInfo.GetAccessControl();
                var rules = dirSecurity.GetAccessRules(true, true, typeof(NTAccount));

                Console.WriteLine($"디렉토리: {Path.GetFileName(directoryPath)}");
                Console.WriteLine($"경로: {directoryPath}\n");

                Console.WriteLine("=== 접근 권한 ===\n");
                foreach (FileSystemAccessRule rule in rules)
                {
                    Console.WriteLine($"사용자: {rule.IdentityReference}");
                    Console.WriteLine($"권한: {rule.FileSystemRights}");
                    Console.WriteLine($"유형: {rule.AccessControlType}");
                    Console.WriteLine();
                }

                CheckRiskFactors(dirSecurity);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"오류: {ex.Message}");
            }
        }

        private void CheckRiskFactors(FileSystemSecurity security)
        {
            Console.WriteLine("=== 보안 위험 평가 ===\n");

            var rules = security.GetAccessRules(true, true, typeof(NTAccount));
            bool hasPublicAccess = false;
            bool hasFullControl = false;

            foreach (FileSystemAccessRule rule in rules)
            {
                string identity = rule.IdentityReference.Value;
                
                if (identity.Contains("Everyone") || identity.Contains("NETWORK SERVICE"))
                {
                    hasPublicAccess = true;
                }

                if (rule.FileSystemRights.HasFlag(FileSystemRights.FullControl))
                {
                    hasFullControl = true;
                }
            }

            if (hasPublicAccess)
            {
                Console.WriteLine("⚠ 경고: 공개 접근 권한이 설정되어 있습니다.");
            }

            if (hasFullControl)
            {
                Console.WriteLine("⚠ 경고: 전체 제어 권한이 설정되어 있습니다.");
            }

            if (!hasPublicAccess && !hasFullControl)
            {
                Console.WriteLine("✓ 권한 설정이 적절합니다.");
            }

            Console.WriteLine();
        }

        public void MonitorDirectoryChanges(string directoryPath, int durationSeconds = 30)
        {
            if (!Directory.Exists(directoryPath))
            {
                Console.WriteLine("디렉토리를 찾을 수 없습니다.");
                return;
            }

            Console.WriteLine($"디렉토리 모니터링 시작: {directoryPath}");
            Console.WriteLine($"모니터링 시간: {durationSeconds}초\n");

            var initialFiles = new Dictionary<string, DateTime>();
            foreach (var file in Directory.GetFiles(directoryPath))
            {
                initialFiles[file] = File.GetLastWriteTime(file);
            }

            var startTime = DateTime.Now;
            var changes = new List<string>();

            while ((DateTime.Now - startTime).TotalSeconds < durationSeconds)
            {
                var currentFiles = Directory.GetFiles(directoryPath);

                foreach (var file in currentFiles)
                {
                    var lastWrite = File.GetLastWriteTime(file);
                    
                    if (!initialFiles.ContainsKey(file))
                    {
                        changes.Add($"✓ 새 파일: {Path.GetFileName(file)}");
                    }
                    else if (initialFiles[file] != lastWrite)
                    {
                        changes.Add($"⚠ 수정됨: {Path.GetFileName(file)}");
                    }
                }

                foreach (var file in initialFiles.Keys)
                {
                    if (!File.Exists(file))
                    {
                        changes.Add($"✗ 삭제됨: {Path.GetFileName(file)}");
                    }
                }

                System.Threading.Thread.Sleep(1000);
            }

            if (changes.Count == 0)
            {
                Console.WriteLine("변경사항이 없습니다.\n");
            }
            else
            {
                Console.WriteLine($"감지된 변경사항 {changes.Count}개:\n");
                foreach (var change in changes)
                {
                    Console.WriteLine(change);
                }
                Console.WriteLine();
            }
        }

        private string FormatFileSize(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB" };
            double len = bytes;
            int order = 0;
            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len = len / 1024;
            }
            return $"{len:0.##} {sizes[order]}";
        }
    }
}
