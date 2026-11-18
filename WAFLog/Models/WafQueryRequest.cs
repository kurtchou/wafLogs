namespace WAFLog.Models;

public class WafQueryRequest
{
    // Defaults to last 7 days in Taipei time (UTC+8)
    public DateTime? StartDate { get; set; }
    public DateTime? EndDate { get; set; }

    // Optional WebACL filter, e.g. ["CreatedByCloudFront-dd96c183"]
    public List<string>? WebAclNames { get; set; }

    // Optional filters: "BLOCK", "ALLOW", "COUNT", or null for all
    public string? Action { get; set; }
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