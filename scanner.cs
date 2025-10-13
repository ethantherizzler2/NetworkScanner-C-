using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using NetworkScanner.Utils;

namespace NetworkScanner.Scanner
{
    public class Scanner
    {

        public async Task<List<ScanResult>> RunAsync(string? cidrOrNull = null,
            int maxConcurrentPings = 200,
            int[]? portsToProbe = null,
            int probePortTimeoutMs = 300)
        {
            var subnet = cidrOrNull ?? GetLocalSubnetCidr();
            if (subnet == null)
            {
                Console.WriteLine("failed to detect local IPv4/subnet . Pass it as argument like 192.168.1.0/24)");
                return new List<ScanResult>();
            }

            Console.WriteLine($"Scanning {subnet} ...");
            var ips = CidrToIpRange(subnet).ToList();
            var results = new List<ScanResult>();
            var throttler = new SemaphoreSlim(maxConcurrentPings);

            var tasks = ips.Select(async ip =>
            {
                await throttler.WaitAsync();
                try
                {
                    var r = await ScanIpAsync(ip, portsToProbe ?? Array.Empty<int>(), probePortTimeoutMs);
                    lock (results) results.Add(r);
                    return r;
                }
                finally
                {
                    throttler.Release();
                }
            }).ToArray();

            await Task.WhenAll(tasks);

            return results.OrderByDescending(r => r.IsAlive).ThenBy(r => IPAddress.Parse(r.Ip).GetAddressBytes().Aggregate(0, (acc, b) => acc * 256 + b)).ToList();
        }

        private async Task<ScanResult> ScanIpAsync(string ip, int[] ports, int portTimeout)
        {
            var res = new ScanResult { Ip = ip, IsAlive = false };

            // Ping
            try
            {
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(ip, 800);
                res.IsAlive = reply.Status == IPStatus.Success;
                if (res.IsAlive) res.PingMs = reply.RoundtripTime;
            }
            catch {  } // ignore

            if (res.IsAlive)
            {
                try
                {
                    var host = await Dns.GetHostEntryAsync(ip);
                    res.Hostname = host.HostName;
                }
                catch {  }

                try
                {
                    res.Mac = ArpUtils.GetMacAddress(ip);
                }
                catch {  }

                // Port probe // added it as test not sure
                if (ports != null && ports.Length > 0)
                {
                    var open = new List<int>();
                    foreach (var p in ports)
                    {
                        if (await IsTcpPortOpenAsync(ip, p, portTimeout))
                            open.Add(p);
                    }
                    res.OpenPorts = open;
                }
            }

            return res;
        }

        private async Task<bool> IsTcpPortOpenAsync(string ip, int port, int timeoutMs)
        {
            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(ip, port);
                var t = await Task.WhenAny(connectTask, Task.Delay(timeoutMs));
                if (t != connectTask) return false;
                return client.Connected;
            }
            catch { return false; }
        }


        public async Task SaveJsonAsync(IEnumerable<ScanResult> results, string path)
        {
            var json = JsonSerializer.Serialize(results, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(path, json, Encoding.UTF8);
        }

        public async Task SaveCsvAsync(IEnumerable<ScanResult> results, string path)
        {
            var sb = new StringBuilder();
            sb.AppendLine("ip,is_alive,ping_ms,hostname,mac,open_ports");
            foreach (var r in results)
            {
                var ports = r.OpenPorts != null && r.OpenPorts.Count > 0 ? string.Join(";", r.OpenPorts) : "";
                sb.AppendLine($"{r.Ip},{r.IsAlive},{r.PingMs ?? -1},\"{r.Hostname}\",\"{r.Mac}\",\"{ports}\"");
            }
            await File.WriteAllTextAsync(path, sb.ToString(), Encoding.UTF8);
        }

        //  guess local IPv4 + netmask 
        private string? GetLocalSubnetCidr()
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                var props = ni.GetIPProperties();
                foreach (var ua in props.UnicastAddresses)
                {
                    if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                    var ip = ua.Address;
                    var mask = ua.IPv4Mask ?? UAtoMask(ua.PrefixLength);
                    if (mask == null) continue;

                    var network = GetNetworkAddress(ip, mask);
                    int prefix = MaskToPrefixLength(mask);
                    return $"{network}/{prefix}";
                }
            }
            return null;
        }

        private static IPAddress? UAtoMask(int prefixLength)
        {
            try
            {
                uint mask = prefixLength == 0 ? 0 : 0xffffffff << (32 - prefixLength);
                return new IPAddress(BitConverter.GetBytes(mask).Reverse().ToArray());
            }
            catch { return null; }
        }

        private static string GetNetworkAddress(IPAddress address, IPAddress subnetMask)
        {
            var ipAddressBytes = address.GetAddressBytes();
            var subnetMaskBytes = subnetMask.GetAddressBytes();

            var broadcastAddress = new byte[ipAddressBytes.Length];
            for (int i = 0; i < broadcastAddress.Length; i++)
            {
                broadcastAddress[i] = (byte)(ipAddressBytes[i] & (subnetMaskBytes[i]));
            }
            return new IPAddress(broadcastAddress).ToString();
        }

        private static int MaskToPrefixLength(IPAddress mask)
        {
            var bytes = mask.GetAddressBytes();
            int count = 0;
            foreach (var b in bytes)
            {
                count += Convert.ToString(b, 2).Count(c => c == '1');
            }
            return count;
        }

        // Expand CIDR to individual IPs (skips network and broadcast ts ahh)
        public static IEnumerable<string> CidrToIpRange(string cidr)
        {
            var parts = cidr.Split('/');
            if (parts.Length != 2) yield break;
            var ip = IPAddress.Parse(parts[0]);
            int prefix = int.Parse(parts[1]);

            uint ipUint = IpToUint(ip);
            int hostBits = 32 - prefix;
            if (hostBits <= 0) { yield return ip.ToString(); yield break; }

            uint numberOfIps = (uint)(1 << hostBits);
            // start at network + 1, end at broadcast -1 (if large networks you gota do different behavior)
            uint start = ipUint + 1;
            uint last = ipUint + numberOfIps - 2;
            for (uint current = start; current <= last; current++)
                yield return UintToIp(current).ToString();
        }

        private static uint IpToUint(IPAddress ip)
        {
            var bytes = ip.GetAddressBytes();
            if (BitConverter.IsLittleEndian)
                Array.Reverse(bytes);
            return BitConverter.ToUInt32(bytes, 0);
        }

        private static IPAddress UintToIp(uint ipUint)
        {
            var bytes = BitConverter.GetBytes(ipUint);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(bytes);
            return new IPAddress(bytes);
        }
    }
}


