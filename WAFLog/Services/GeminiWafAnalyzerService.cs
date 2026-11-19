using System.Text.Json;
using Google.GenAI;
using WAFLog.Models;

namespace WAFLog.Services;

public interface IGeminiWafAnalyzerService
{
    Task<string> SummarizeThreatLogsAsync(
        List<WafLogSummaryRow> logs,
        string? customPrompt = null,
        CancellationToken ct = default);
}

public class GeminiWafAnalyzerService : IGeminiWafAnalyzerService
{
    private readonly Client _geminiClient;
    private readonly string _model;
    private readonly ILogger<GeminiWafAnalyzerService> _logger;

    public GeminiWafAnalyzerService(
        IConfiguration config,
        ILogger<GeminiWafAnalyzerService> logger)
    {
        _logger = logger;
        var apiKey = config["Gemini:ApiKey"]
            ?? Environment.GetEnvironmentVariable("GEMINI_API_KEY")
            ?? throw new InvalidOperationException("Gemini:ApiKey is not configured.");

        _model = config["Gemini:Model"] ?? "gemini-3.6-flash";
        _geminiClient = new Client(apiKey: apiKey);
    }

    public async Task<string> SummarizeThreatLogsAsync(
        List<WafLogSummaryRow> logs,
        string? customPrompt = null,
        CancellationToken ct = default)
    {
        if (logs.Count == 0)
            return "### No WAF Events Found\nNo matching AWS WAF log entries were found for the selected date range and filters.";

        var serializedLogs = JsonSerializer.Serialize(logs, new JsonSerializerOptions
        {
            WriteIndented = false
        });

        var userQuestion = string.IsNullOrWhiteSpace(customPrompt)
            ? "Provide an executive security summary of these AWS WAF events."
            : customPrompt.Trim();

        var prompt = $@"
You are a senior cloud security engineer analyzing aggregated AWS WAF logs for Qware's web infrastructure (timestamps are in Asia/Taipei UTC+8).

User Focus: {userQuestion}

Analyze the JSON log summary below and respond in clean, scannable Markdown with these exact sections:
1. **Threat Overview & Severity** (Low / Medium / High — summarize total blocked vs allowed patterns and primary rules triggered)
2. **Top Source IPs & Behavioral Patterns** (Identify automated scanners, path probing like `/huiwan/ipcheck.aspx`, credential stuffing, or false-positive internal/cloud IPs such as AWS/LINE/Taiwan ISP ranges)
3. **Targeted Endpoints & Rules** (Which URIs and `TerminatingRuleId` rules are seeing the most hits)
4. **Recommended Actions** (Concrete WAF rule tuning, IP allowlisting, or rate-based rule adjustments)

Aggregated WAF Logs (JSON):
{serializedLogs}";

        _logger.LogInformation("Sending {RowCount} aggregated WAF patterns to Gemini ({Model})", logs.Count, _model);

        var response = await _geminiClient.Models.GenerateContentAsync(
            model: _model,
            contents: prompt,
            cancellationToken: ct);

        return response.Candidates?
            .FirstOrDefault()?
            .Content?
            .Parts?
            .FirstOrDefault()?
            .Text
            ?? "Gemini returned an empty analysis response.";
    }
}