using System;
using System.IO;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Collections.Generic;
using System.Threading.Tasks;

public class Collector
{
    // Главная функция по заданию
    public void collect(String out_dir)
    {
        Task.Run(async () => await Run(out_dir)).Wait();
    }

    private async Task Run(string out_dir)
    {
        Directory.CreateDirectory(out_dir);

        string url = "https://security.archlinux.org/issues/all.json";

        using HttpClient client = new HttpClient();

        Console.WriteLine("Downloading Arch Security Bulletin...");

        string jsonText = await client.GetStringAsync(url);

        var issues = JsonSerializer.Deserialize<List<ArchIssue>>(jsonText);

        if (issues == null)
        {
            Console.WriteLine("Failed to parse JSON.");
            return;
        }

        List<ResultEntry> result = new List<ResultEntry>();

        foreach (var issue in issues)
        {
            if (issue.Packages == null)
                continue;

            foreach (var pkg in issue.Packages)
            {
                result.Add(new ResultEntry
                {
                    package = pkg,

                    cve = issue.Issues ?? new List<string>(),

                    version = new VersionInfo
                    {
                        from = issue.Affected,
                        to = issue.Fixed,
                        include_from = true,
                        include_to = false
                    }
                });
            }
        }

        string outputFile = Path.Combine(out_dir, "arch_security.json");

        var options = new JsonSerializerOptions
        {
            WriteIndented = true
        };

        File.WriteAllText(outputFile, JsonSerializer.Serialize(result, options));

        Console.WriteLine("Done!");
        Console.WriteLine("Saved to: " + outputFile);
    }
}

public class ArchIssue
{
    // packages = список пакетов
    [JsonPropertyName("packages")]
    public List<string> Packages { get; set; }

    // issues = список CVE
    [JsonPropertyName("issues")]
    public List<string> Issues { get; set; }

    // affected version
    [JsonPropertyName("affected")]
    public string Affected { get; set; }

    // fixed version
    [JsonPropertyName("fixed")]
    public string Fixed { get; set; }
}

public class ResultEntry
{
    public string package { get; set; }
    public List<string> cve { get; set; }
    public VersionInfo version { get; set; }
}

public class VersionInfo
{
    public string from { get; set; }
    public string to { get; set; }

    public bool include_from { get; set; }
    public bool include_to { get; set; }
}