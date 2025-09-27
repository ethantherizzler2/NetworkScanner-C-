using System.Collections.Generic;

namespace NetworkScanner.Scanner
{
    public class ScanResult
    {
        public string Ip { get; set; } = string.Empty;
        public bool IsAlive { get; set; }
        public long? PingMs { get; set; }
        public string? Hostname { get; set; }
        public string? Mac { get; set; }
        public List<int> OpenPorts { get; set; } = new();
    }
}
