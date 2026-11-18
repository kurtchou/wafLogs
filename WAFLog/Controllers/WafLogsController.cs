using Microsoft.AspNetCore.Mvc;
using WAFLog.Models;
using WAFLog.Services;

namespace WAFLog.Controllers;

[ApiController]
[Route("api/[controller]")]
public class WafLogsController : ControllerBase
{
    private readonly IAthenaQueryService _athenaService;

    public WafLogsController(IAthenaQueryService athenaService)
    {
        _athenaService = athenaService;
    }

    [HttpPost("query")]
    public async Task<ActionResult<List<WafLogSummaryRow>>> QueryLogs(
        [FromBody] WafQueryRequest request,
        CancellationToken ct)
    {
        var rows = await _athenaService.QueryWafLogsAsync(request, ct);
        return Ok(rows);
    }
}