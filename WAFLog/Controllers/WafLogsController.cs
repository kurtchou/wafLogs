using Microsoft.AspNetCore.Mvc;
using WAFLog.Models;
using WAFLog.Services;

namespace WAFLog.Controllers;

[ApiController]
[Route("api/[controller]")]
public class WafLogsController : ControllerBase
{
    private readonly IAthenaQueryService _athenaService;
    private readonly IGeminiWafAnalyzerService _geminiService;

    public WafLogsController(
            IAthenaQueryService athenaService,
            IGeminiWafAnalyzerService geminiService)
    {
        _athenaService = athenaService;
        _geminiService = geminiService;
    }

    [HttpPost("query")]
    public async Task<ActionResult<List<WafLogSummaryRow>>> QueryLogs(
     [FromBody] WafQueryRequest request,
     CancellationToken ct)
    {
        var validActions = request.Actions?
            .Where(a => !string.IsNullOrWhiteSpace(a))
            .ToList();

        if (validActions is not { Count: > 0 })
        {
            return BadRequest(new { error = "At least one action (e.g. BLOCK, ALLOW) is required." });
        }

        request.Actions = validActions;
        var rows = await _athenaService.QueryWafLogsAsync(request, ct);
        return Ok(rows);
    }

    [HttpPost("analyze")]
    public async Task<ActionResult<WafAnalyzeResponse>> AnalyzeLogs(
     [FromBody] WafAnalyzeRequest request,
     CancellationToken ct)
    {
        // Reuse pre-fetched rows if provided; only hit Athena as a fallback
        var rows = (request.Logs is { Count: > 0 })
            ? request.Logs
            : await _athenaService.QueryWafLogsAsync(request, ct);

        if (rows.Count == 0)
        {
            return Ok(new WafAnalyzeResponse
            {
                GeneratedAtTaipei = DateTime.UtcNow.AddHours(8).ToString("yyyy-MM-dd HH:mm:ss"),
                TotalUniquePatterns = 0,
                TotalRequestsAnalyzed = 0,
                AiSummaryMarkdown = "沒有資料我無法回復",
                Logs = rows
            });
        }

        var markdown = await _geminiService.SummarizeThreatLogsAsync(rows, request.CustomPrompt, ct);

        return Ok(new WafAnalyzeResponse
        {
            GeneratedAtTaipei = DateTime.UtcNow.AddHours(8).ToString("yyyy-MM-dd HH:mm:ss"),
            TotalUniquePatterns = rows.Count,
            TotalRequestsAnalyzed = rows.Sum(r => r.RequestCount),
            AiSummaryMarkdown = markdown,
            // Optional: return empty list if client already has `rows` to save response bandwidth
            Logs = rows
        });
    }
}