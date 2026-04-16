using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Collections.Generic;
using System.Linq;

namespace SecurityToolkit.Tools
{
    public class NetworkTrafficAnalyzer
    {
        public void GetNetworkInterfaces()
        {
            Console.WriteLine("=== 네트워크 인터페이스 ===\n");

            var interfaces = NetworkInterface.GetAllNetworkInterfaces();
            
            if (interfaces.Length == 0)
            {
                Console.WriteLine("네트워크 인터페이스를 찾을 수 없습니다.\n");
                return;
            }

            foreach (var ni in interfaces)
            {
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

                Console.WriteLine($"인터페이스: {ni.Name}");
                Console.WriteLine($"설명: {ni.Description}");
                Console.WriteLine($"상태: {ni.OperationalStatus}");
                Console.WriteLine($"타입: {ni.NetworkInterfaceType}");

                var ipProps = ni.GetIPProperties();
                foreach (var ip in ipProps.UnicastAddresses)
                {
                    if (ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        Console.WriteLine($"IPv4: {ip.Address}");
                    }
                }

                var stats = ni.GetIPStatistics();
                Console.WriteLine($"송신: {FormatBytes(stats.BytesSent)}");
                Console.WriteLine($"수신: {FormatBytes(stats.BytesReceived)}");
                Console.WriteLine();
            }
        }

        public void AnalyzeNetworkStatistics()
        {
            Console.WriteLine("=== 네트워크 통계 ===\n");

            var interfaces = NetworkInterface.GetAllNetworkInterfaces();
            long totalBytesSent = 0;
            long totalBytesReceived = 0;

            foreach (var ni in interfaces)
            {
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

                var stats = ni.GetIPStatistics();
                totalBytesSent += stats.BytesSent;
                totalBytesReceived += stats.BytesReceived;
            }

            Console.WriteLine($"총 송신: {FormatBytes(totalBytesSent)}");
            Console.WriteLine($"총 수신: {FormatBytes(totalBytesReceived)}");
            Console.WriteLine($"총 트래픽: {FormatBytes(totalBytesSent + totalBytesReceived)}\n");
        }

        public void GetActiveConnections()
        {
            Console.WriteLine("=== 활성 네트워크 연결 ===\n");

            try
            {
                var tcpConnections = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();
                
                if (tcpConnections.Length == 0)
                {
                    Console.WriteLine("활성 TCP 연결이 없습니다.\n");
                    return;
                }

                Console.WriteLine($"총 {tcpConnections.Length}개 연결:\n");

                var groupedByState = tcpConnections.GroupBy(c => c.State);
                foreach (var group in groupedByState)
                {
                    Console.WriteLine($"{group.Key}: {group.Count()}개");
                }

                Console.WriteLine("\n상세 연결 정보 (처음 10개):\n");
                foreach (var connection in tcpConnections.Take(10))
                {
                    Console.WriteLine($"로컬: {connection.LocalEndPoint}");
                    Console.WriteLine($"원격: {connection.RemoteEndPoint}");
                    Console.WriteLine($"상태: {connection.State}");
                    Console.WriteLine();
                }

                if (tcpConnections.Length > 10)
                {
                    Console.WriteLine($"... 외 {tcpConnections.Length - 10}개 더 있습니다.\n");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"오류: {ex.Message}\n");
            }
        }

        public void MonitorBandwidth(int durationSeconds = 10)
        {
            Console.WriteLine($"대역폭 모니터링 중 ({durationSeconds}초)...\n");

            var interfaces = NetworkInterface.GetAllNetworkInterfaces()
                .Where(ni => ni.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .ToArray();

            var initialStats = new Dictionary<string, (long sent, long received)>();
            foreach (var ni in interfaces)
            {
                var stats = ni.GetIPStatistics();
                initialStats[ni.Name] = (stats.BytesSent, stats.BytesReceived);
            }

            System.Threading.Thread.Sleep(durationSeconds * 1000);

            Console.WriteLine("=== 대역폭 사용량 ===\n");

            foreach (var ni in interfaces)
            {
                var stats = ni.GetIPStatistics();
                var (initialSent, initialReceived) = initialStats[ni.Name];

                long sentDiff = stats.BytesSent - initialSent;
                long receivedDiff = stats.BytesReceived - initialReceived;

                double sentPerSec = sentDiff / (double)durationSeconds;
                double receivedPerSec = receivedDiff / (double)durationSeconds;

                Console.WriteLine($"인터페이스: {ni.Name}");
                Console.WriteLine($"송신: {FormatBytes(sentPerSec)}/s");
                Console.WriteLine($"수신: {FormatBytes(receivedPerSec)}/s");
                Console.WriteLine();
            }
        }

        public void CheckDNSServers()
        {
            Console.WriteLine("=== DNS 서버 ===\n");

            try
            {
                var ipProps = IPGlobalProperties.GetIPGlobalProperties();
                var dnsServers = ipProps.GetNetworkParams().DnsAddresses;

                if (dnsServers.Length == 0)
                {
                    Console.WriteLine("DNS 서버를 찾을 수 없습니다.\n");
                    return;
                }

                Console.WriteLine($"설정된 DNS 서버 {dnsServers.Length}개:\n");
                foreach (var dns in dnsServers)
                {
                    Console.WriteLine($"  {dns}");
                }
                Console.WriteLine();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"오류: {ex.Message}\n");
            }
        }

        private string FormatBytes(double bytes)
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
