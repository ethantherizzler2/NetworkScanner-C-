using System;
using System.IO;
using System.Threading.Tasks;
using NetworkScanner;

class Program
{
    static async Task<int> Main(string[] args)
    {
        Console.WriteLine("starting...");
        var scanner = new NetworkScanner.Scanner.Scanner();

        //  allow to pass a subnet like "192.168.1.0/24"
        string? subnetArg = args.Length > 0 ? args[0] : null;
        var results = await scanner.RunAsync(subnetArg,
            maxConcurrentPings: 200,
            portsToProbe: new int[] { 22, 80, 443, 3389 }, // can change this
            probePortTimeoutMs: 250);

        string outCsv = Path.Combine(Directory.GetCurrentDirectory(), $"scan_{DateTime.UtcNow:yyyyMMdd_HHmmss}.csv");
        await scanner.SaveCsvAsync(results, outCsv);

        string outJson = Path.Combine(Directory.GetCurrentDirectory(), $"scan_{DateTime.UtcNow:yyyyMMdd_HHmmss}.json");
        await scanner.SaveJsonAsync(results, outJson);

        Console.WriteLine($"Scan done. CSV: {outCsv}");
        Console.WriteLine($"JSON: {outJson}");
        Console.WriteLine("Example: run `dotnet run -- 192.168.1.0/24` to scan that subnet only");
        return 0;
    }
}

