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
        var rows = await _athenaService.QueryWafLogsAsync(request, ct);
        return Ok(rows);
    }

    [HttpPost("analyze")]
    public async Task<ActionResult<WafAnalyzeResponse>> AnalyzeLogs(
        [FromBody] WafAnalyzeRequest request,
        CancellationToken ct)
    {
        var rows = await _athenaService.QueryWafLogsAsync(request, ct);
        var markdown = await _geminiService.SummarizeThreatLogsAsync(rows, request.CustomPrompt, ct);

        return Ok(new WafAnalyzeResponse
        {
            GeneratedAtTaipei = DateTime.UtcNow.AddHours(8).ToString("yyyy-MM-dd HH:mm:ss"),
            TotalUniquePatterns = rows.Count,
            TotalRequestsAnalyzed = rows.Sum(r => r.RequestCount),
            AiSummaryMarkdown = markdown,
            Logs = rows
        });
    }
}