using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace NetworkScanner.Utils
{
    public static class ArpUtils
    {
        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        static extern int SendARP(uint destIp, uint srcIp, byte[] macAddr, ref uint phyAddrLen);

        public static string? GetMacAddress(string ip)
        {
            if (!IPAddress.TryParse(ip, out var addr)) return null;
            uint dest = BitConverter.ToUInt32(addr.GetAddressBytes(), 0);
            uint src = 0;
            byte[] macAddr = new byte[6];
            uint length = (uint)macAddr.Length;
            try
            {
                int res = SendARP(dest, src, macAddr, ref length);
                if (res != 0) return null;
                var sb = new StringBuilder();
                for (int i = 0; i < length; i++)
                {
                    if (sb.Length > 0) sb.Append(':');
                    sb.Append(macAddr[i].ToString("X2"));
                }
                return sb.ToString();
            }
            catch
            {
                return null;
            }
        }
    }
}
