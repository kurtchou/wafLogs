namespace WAFLog.Models;

public class WafQueryRequest
{
    // Defaults to last 7 days in Taipei time (UTC+8)
    public DateTime? StartDate { get; set; }
    public DateTime? EndDate { get; set; }

    // Optional WebACL filter, e.g. ["CreatedByCloudFront-dd96c183"]
    public List<string>? WebAclNames { get; set; }

    public List<string>? Actions { get; set; }
    // Optional filters: "BLOCK", "ALLOW", "COUNT", or null for all
    // 
    public string? ClientIp { get; set; }
    public int Limit { get; set; } = 100;
}

public class WafLogSummaryRow
{
    public string WebAclName { get; set; } = string.Empty;
    public string LatestTaipeiTime { get; set; } = string.Empty;
    public string Action { get; set; } = string.Empty;
    public string TerminatingRuleId { get; set; } = string.Empty;
    public string ClientIp { get; set; } = string.Empty;
    public string Country { get; set; } = string.Empty;
    public string HttpMethod { get; set; } = string.Empty;
    public string Host { get; set; } = string.Empty;
    public string Uri { get; set; } = string.Empty;
    public string UserAgent { get; set; } = string.Empty;
    public long RequestCount { get; set; }
}

public class WafAnalyzeRequest : WafQueryRequest
{
    // Optional custom question from the user in the UI, e.g. "Are any of these IPs legitimate internal testers?"
    public string? CustomPrompt { get; set; }
    public List<WafLogSummaryRow>? Logs { get; set; }
}

public class WafAnalyzeResponse
{
    public string GeneratedAtTaipei { get; set; } = string.Empty;
    public int TotalUniquePatterns { get; set; }
    public long TotalRequestsAnalyzed { get; set; }
    public string AiSummaryMarkdown { get; set; } = string.Empty;
    public List<WafLogSummaryRow> Logs { get; set; } = new();
}