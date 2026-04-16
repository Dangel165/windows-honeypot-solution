using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace SecurityToolkit.Tools
{
    public class LogAnalyzer
    {
        private List<LogEntry> logs = new();

        public class LogEntry
        {
            public DateTime Timestamp { get; set; }
            public string Level { get; set; }
            public string Message { get; set; }
            public string Source { get; set; }
        }

        public void AnalyzeLogFile(string filePath)
        {
            if (!File.Exists(filePath))
            {
                Console.WriteLine("로그 파일을 찾을 수 없습니다.");
                return;
            }

            try
            {
                logs.Clear();
                var lines = File.ReadAllLines(filePath);
                Console.WriteLine($"로그 파일 분석 중: {Path.GetFileName(filePath)}");
                Console.WriteLine($"총 {lines.Length}줄 처리 중...\n");

                foreach (var line in lines)
                {
                    ParseLogLine(line);
                }

                DisplayAnalysis();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"오류: {ex.Message}");
            }
        }

        private void ParseLogLine(string line)
        {
            if (string.IsNullOrWhiteSpace(line)) return;

            var entry = new LogEntry
            {
                Message = line,
                Level = ExtractLogLevel(line),
                Source = ExtractSource(line)
            };

            logs.Add(entry);
        }

        private string ExtractLogLevel(string line)
        {
            if (line.Contains("ERROR", StringComparison.OrdinalIgnoreCase)) return "ERROR";
            if (line.Contains("WARN", StringComparison.OrdinalIgnoreCase)) return "WARN";
            if (line.Contains("INFO", StringComparison.OrdinalIgnoreCase)) return "INFO";
            if (line.Contains("DEBUG", StringComparison.OrdinalIgnoreCase)) return "DEBUG";
            return "UNKNOWN";
        }

        private string ExtractSource(string line)
        {
            var match = Regex.Match(line, @"\[([^\]]+)\]");
            return match.Success ? match.Groups[1].Value : "Unknown";
        }

        private void DisplayAnalysis()
        {
            if (logs.Count == 0)
            {
                Console.WriteLine("분석할 로그가 없습니다.\n");
                return;
            }

            var errorCount = logs.Count(l => l.Level == "ERROR");
            var warnCount = logs.Count(l => l.Level == "WARN");
            var infoCount = logs.Count(l => l.Level == "INFO");

            Console.WriteLine("=== 로그 분석 결과 ===\n");
            Console.WriteLine($"총 로그 수: {logs.Count}");
            Console.WriteLine($"  ✗ ERROR: {errorCount}");
            Console.WriteLine($"  ⚠ WARN:  {warnCount}");
            Console.WriteLine($"  ℹ INFO:  {infoCount}\n");

            if (errorCount > 0)
            {
                Console.WriteLine("=== 의심 활동 감지 ===\n");
                var suspiciousLogs = logs.Where(l => l.Level == "ERROR").Take(5);
                foreach (var log in suspiciousLogs)
                {
                    Console.WriteLine($"✗ {log.Message}");
                }
                if (errorCount > 5)
                {
                    Console.WriteLine($"... 외 {errorCount - 5}개 더 있습니다.");
                }
                Console.WriteLine();
            }

            DetectAnomalies();
        }

        private void DetectAnomalies()
        {
            Console.WriteLine("=== 이상 탐지 ===\n");

            var failedLogins = logs.Count(l => l.Message.Contains("failed", StringComparison.OrdinalIgnoreCase) 
                                            && l.Message.Contains("login", StringComparison.OrdinalIgnoreCase));
            if (failedLogins > 5)
            {
                Console.WriteLine($"⚠ 실패한 로그인 시도 {failedLogins}회 감지");
            }

            var accessDenied = logs.Count(l => l.Message.Contains("access denied", StringComparison.OrdinalIgnoreCase));
            if (accessDenied > 3)
            {
                Console.WriteLine($"⚠ 접근 거부 {accessDenied}회 감지");
            }

            var suspiciousIPs = logs.Where(l => Regex.IsMatch(l.Message, @"\b(?:\d{1,3}\.){3}\d{1,3}\b"))
                                   .GroupBy(l => Regex.Match(l.Message, @"\b(?:\d{1,3}\.){3}\d{1,3}\b").Value)
                                   .Where(g => g.Count() > 3);

            foreach (var ipGroup in suspiciousIPs)
            {
                Console.WriteLine($"⚠ 의심 IP {ipGroup.Key}에서 {ipGroup.Count()}회 접근");
            }

            Console.WriteLine();
        }

        public void GenerateReport(string outputPath)
        {
            try
            {
                using (var writer = new StreamWriter(outputPath))
                {
                    writer.WriteLine("=== 보안 로그 분석 보고서 ===");
                    writer.WriteLine($"생성 시간: {DateTime.Now:yyyy-MM-dd HH:mm:ss}\n");
                    writer.WriteLine($"총 로그 수: {logs.Count}");
                    writer.WriteLine($"ERROR: {logs.Count(l => l.Level == "ERROR")}");
                    writer.WriteLine($"WARN: {logs.Count(l => l.Level == "WARN")}");
                    writer.WriteLine($"INFO: {logs.Count(l => l.Level == "INFO")}\n");

                    writer.WriteLine("=== 상세 로그 ===\n");
                    foreach (var log in logs.Take(100))
                    {
                        writer.WriteLine($"[{log.Level}] {log.Message}");
                    }
                }

                Console.WriteLine($"✓ 보고서 생성 완료: {outputPath}\n");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"오류: {ex.Message}");
            }
        }
    }
}
