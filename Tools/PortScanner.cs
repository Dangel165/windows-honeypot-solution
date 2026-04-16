using System;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Collections.Generic;

namespace SecurityToolkit.Tools
{
    public class PortScanner
    {
        private static readonly Dictionary<int, string> CommonPorts = new()
        {
            { 21, "FTP" },
            { 22, "SSH" },
            { 23, "Telnet" },
            { 25, "SMTP" },
            { 53, "DNS" },
            { 80, "HTTP" },
            { 110, "POP3" },
            { 143, "IMAP" },
            { 443, "HTTPS" },
            { 445, "SMB" },
            { 3306, "MySQL" },
            { 3389, "RDP" },
            { 5432, "PostgreSQL" },
            { 5900, "VNC" },
            { 8080, "HTTP-Alt" },
            { 8443, "HTTPS-Alt" }
        };

        public void ScanHost(string host, int startPort = 1, int endPort = 1024)
        {
            Console.WriteLine($"호스트 스캔 중: {host}");
            Console.WriteLine($"포트 범위: {startPort} - {endPort}\n");

            var openPorts = new List<int>();
            var tasks = new List<Task>();

            for (int port = startPort; port <= endPort; port++)
            {
                int currentPort = port;
                tasks.Add(Task.Run(() =>
                {
                    if (IsPortOpen(host, currentPort))
                    {
                        lock (openPorts)
                        {
                            openPorts.Add(currentPort);
                        }
                    }
                }));

                if (tasks.Count >= 50)
                {
                    Task.WaitAll(tasks.ToArray());
                    tasks.Clear();
                }
            }

            Task.WaitAll(tasks.ToArray());

            if (openPorts.Count == 0)
            {
                Console.WriteLine("열린 포트가 없습니다.\n");
                return;
            }

            Console.WriteLine($"✓ 열린 포트 {openPorts.Count}개 발견:\n");
            foreach (var port in openPorts)
            {
                string service = CommonPorts.ContainsKey(port) ? CommonPorts[port] : "Unknown";
                Console.WriteLine($"  포트 {port:D5} - {service}");
            }
            Console.WriteLine();
        }

        public void ScanCommonPorts(string host)
        {
            Console.WriteLine($"일반 포트 스캔: {host}\n");
            var openPorts = new List<int>();

            foreach (var port in CommonPorts.Keys)
            {
                if (IsPortOpen(host, port))
                {
                    openPorts.Add(port);
                }
            }

            if (openPorts.Count == 0)
            {
                Console.WriteLine("열린 포트가 없습니다.\n");
                return;
            }

            Console.WriteLine($"✓ 열린 포트 {openPorts.Count}개 발견:\n");
            foreach (var port in openPorts)
            {
                string service = CommonPorts[port];
                Console.WriteLine($"  포트 {port:D5} - {service}");
            }
            Console.WriteLine();
        }

        private bool IsPortOpen(string host, int port)
        {
            try
            {
                using (var client = new TcpClient())
                {
                    var result = client.BeginConnect(host, port, null, null);
                    bool success = result.AsyncWaitHandle.WaitOne(TimeSpan.FromMilliseconds(500));
                    
                    if (success)
                    {
                        client.EndConnect(result);
                        return true;
                    }
                    return false;
                }
            }
            catch
            {
                return false;
            }
        }
    }
}
