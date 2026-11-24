using Amazon.Athena;
using Amazon.Athena.Model;
using WAFLog.Models;

namespace WAFLog.Services;

public interface IAthenaQueryService
{
    Task<List<WafLogSummaryRow>> QueryWafLogsAsync(WafQueryRequest request, CancellationToken ct = default);
}

public class AthenaQueryService : IAthenaQueryService
{
    private readonly IAmazonAthena _athena;
    private readonly IConfiguration _config;
    private readonly ILogger<AthenaQueryService> _logger;

    public AthenaQueryService(
        IAmazonAthena athena,
        IConfiguration config,
        ILogger<AthenaQueryService> logger)
    {
        _athena = athena;
        _config = config;
        _logger = logger;
    }

    public async Task<List<WafLogSummaryRow>> QueryWafLogsAsync(WafQueryRequest request, CancellationToken ct = default)
    {
        if (request.Actions is not { Count: > 0 })
            throw new ArgumentException("At least one action is required.", nameof(request.Actions));

        var database = _config["Athena:Database"] ?? "default";
        var tableName = _config["Athena:TableName"] ?? "waf_logs_uat";
        var outputLocation = _config["Athena:OutputLocation"]
            ?? throw new InvalidOperationException("Athena:OutputLocation is missing in configuration.");
        var workGroup = _config["Athena:WorkGroup"] ?? "primary";

        // Default to last 7 days in UTC+8 (Taipei)
        var taipeiNow = DateTime.UtcNow.AddHours(8);
        var endDate = request.EndDate ?? taipeiNow;
        var startDate = request.StartDate ?? endDate.AddDays(-7);
        var limit = Math.Clamp(request.Limit, 1, 500);

        var sql = BuildAggregatedSql(tableName, startDate, endDate, request.WebAclNames, request.Actions, request.ClientIp, limit);
        _logger.LogInformation("Executing Athena WAF query: {Sql}", sql);

        var startResponse = await _athena.StartQueryExecutionAsync(new StartQueryExecutionRequest
        {
            QueryString = sql,
            QueryExecutionContext = new QueryExecutionContext { Database = database },
            ResultConfiguration = new ResultConfiguration { OutputLocation = outputLocation },
            WorkGroup = workGroup
        }, ct);

        var executionId = startResponse.QueryExecutionId;

        await WaitForQueryCompletionAsync(executionId, ct);

        var resultsResponse = await _athena.GetQueryResultsAsync(new GetQueryResultsRequest
        {
            QueryExecutionId = executionId,
            MaxResults = limit + 1
        }, ct);

        var rows = resultsResponse.ResultSet.Rows;
        var parsed = new List<WafLogSummaryRow>();

        for (int i = 1; i < rows.Count; i++)
        {
            var cols = rows[i].Data;
            parsed.Add(new WafLogSummaryRow
            {
                WebAclName = GetCell(cols, 0),
                LatestTaipeiTime = GetCell(cols, 1),
                Action = GetCell(cols, 2),
                TerminatingRuleId = GetCell(cols, 3),
                ClientIp = GetCell(cols, 4),
                Country = GetCell(cols, 5),
                HttpMethod = GetCell(cols, 6),
                Host = GetCell(cols, 7),
                Uri = GetCell(cols, 8),
                UserAgent = GetCell(cols, 9),
                RequestCount = long.TryParse(GetCell(cols, 10), out var count) ? count : 1
            });
        }

        return parsed;
    }

    private static string BuildAggregatedSql(
        string tableName,
        DateTime startDate,
        DateTime endDate,
        List<string>? webAclNames,
        List<string>? actions,
        string? clientIp,
        int limit)
    {
        // Matches your partition projection column: log_date = 'yyyy/MM/dd'
        var startPartition = startDate.ToString("yyyy/MM/dd");
        var endPartition = endDate.ToString("yyyy/MM/dd");

        var whereClauses = new List<string>
        {
            $"log_date BETWEEN '{startPartition}' AND '{endPartition}'"
        };

        if (webAclNames is { Count: > 0 })
        {
            var escapedList = string.Join(", ", webAclNames
                .Where(w => !string.IsNullOrWhiteSpace(w))
                .Select(w => $"'{w.Trim().Replace("'", "")}'"));

            if (!string.IsNullOrEmpty(escapedList))
                whereClauses.Add($"webacl_name IN ({escapedList})");
        }

        if (actions is { Count: > 0 })
        {
            var escapedActions = string.Join(", ", actions
                .Where(a => !string.IsNullOrWhiteSpace(a))
                .Select(a => $"'{a.Trim().ToUpperInvariant().Replace("'", "")}'"));

            if (!string.IsNullOrEmpty(escapedActions))
                whereClauses.Add($"action IN ({escapedActions})");
        }

        if (!string.IsNullOrWhiteSpace(clientIp))
        {
            var safeIp = clientIp.Trim().Replace("'", "");
            whereClauses.Add($"httprequest.clientip = '{safeIp}'");
        }

        var whereSql = string.Join(" AND ", whereClauses);

        return $@"
            SELECT
                webacl_name,
                CAST(date_add('hour', 8, from_unixtime(MAX(timestamp) / 1000)) AS VARCHAR) AS latest_taipei_time,
                action,
                terminatingruleid,
                httprequest.clientip AS client_ip,
                httprequest.country AS country,
                httprequest.httpmethod AS http_method,
                COALESCE(
                    ELEMENT_AT(TRANSFORM(FILTER(httprequest.headers, h -> LOWER(h.name) = 'host'), h -> h.value), 1),
                    '-'
                ) AS host,
                httprequest.uri AS uri,
                COALESCE(
                    ELEMENT_AT(TRANSFORM(FILTER(httprequest.headers, h -> LOWER(h.name) = 'user-agent'), h -> h.value), 1),
                    '-'
                ) AS user_agent,
                COUNT(*) AS request_count
            FROM {tableName}
            WHERE {whereSql}
            GROUP BY
                webacl_name,
                action,
                terminatingruleid,
                httprequest.clientip,
                httprequest.country,
                httprequest.httpmethod,
                COALESCE(ELEMENT_AT(TRANSFORM(FILTER(httprequest.headers, h -> LOWER(h.name) = 'host'), h -> h.value), 1), '-'),
                httprequest.uri,
                COALESCE(ELEMENT_AT(TRANSFORM(FILTER(httprequest.headers, h -> LOWER(h.name) = 'user-agent'), h -> h.value), 1), '-')
            ORDER BY MAX(timestamp) DESC
            LIMIT {limit}";
    }

    private async Task WaitForQueryCompletionAsync(string executionId, CancellationToken ct)
    {
        var delayMs = 500;
        const int maxWaitMs = 45_000;
        var elapsedMs = 0;

        while (elapsedMs < maxWaitMs)
        {
            var statusResponse = await _athena.GetQueryExecutionAsync(new GetQueryExecutionRequest
            {
                QueryExecutionId = executionId
            }, ct);

            var state = statusResponse.QueryExecution.Status.State;

            if (state == QueryExecutionState.SUCCEEDED)
                return;

            if (state == QueryExecutionState.FAILED || state == QueryExecutionState.CANCELLED)
            {
                var reason = statusResponse.QueryExecution.Status.StateChangeReason;
                throw new Exception($"Athena query {executionId} {state}: {reason}");
            }

            await Task.Delay(delayMs, ct);
            elapsedMs += delayMs;
            delayMs = Math.Min(delayMs + 300, 2000); // Gentle backoff up to 2s
        }

        throw new TimeoutException($"Athena query {executionId} timed out after {maxWaitMs}ms.");
    }

    private static string BuildAggregatedSql(
        string tableName,
        DateTime startUtc,
        DateTime endUtc,
        List<string>? actions,
        string? clientIp,
        string? clientIp1,
        int limit)
    {
        // Partition projection filter: 'yyyy/MM/dd/HH' dramatically reduces S3 scan cost
        var startPartition = startUtc.ToString("yyyy/MM/dd/HH");
        var endPartition = endUtc.ToString("yyyy/MM/dd/HH");

        var whereClauses = new List<string>
        {
            $"datehour >= '{startPartition}'",
            $"datehour <= '{endPartition}'"
        };

        if (actions is { Count: > 0 })
        {
            var escapedActions = string.Join(", ", actions
                .Where(a => !string.IsNullOrWhiteSpace(a))
                .Select(a => $"'{a.Trim().ToUpperInvariant().Replace("'", "")}'"));

            if (!string.IsNullOrEmpty(escapedActions))
                whereClauses.Add($"action IN ({escapedActions})");
        }

        if (!string.IsNullOrWhiteSpace(clientIp))
        {
            var safeIp = clientIp.Trim().Replace("'", "");
            whereClauses.Add($"httprequest.clientip = '{safeIp}'");
        }

        var whereSql = string.Join(" AND ", whereClauses);

        // Pre-aggregate repetitive attack bursts so Gemini gets clean signal instead of duplicate rows
        return $@"
            SELECT
                from_unixtime(MAX(timestamp) / 1000) AS latest_utc,
                action,
                terminatingruleid,
                httprequest.clientip AS client_ip,
                httprequest.country AS country,
                httprequest.httpmethod AS http_method,
                COALESCE(
                    ELEMENT_AT(TRANSFORM(FILTER(httprequest.headers, h -> LOWER(h.name) = 'host'), h -> h.value), 1),
                    '-'
                ) AS host,
                httprequest.uri AS uri,
                COALESCE(
                    ELEMENT_AT(TRANSFORM(FILTER(httprequest.headers, h -> LOWER(h.name) = 'user-agent'), h -> h.value), 1),
                    '-'
                ) AS user_agent,
                COUNT(*) AS request_count
            FROM {tableName}
            WHERE {whereSql}
            GROUP BY
                action,
                terminatingruleid,
                httprequest.clientip,
                httprequest.country,
                httprequest.httpmethod,
                COALESCE(ELEMENT_AT(TRANSFORM(FILTER(httprequest.headers, h -> LOWER(h.name) = 'host'), h -> h.value), 1), '-'),
                httprequest.uri,
                COALESCE(ELEMENT_AT(TRANSFORM(FILTER(httprequest.headers, h -> LOWER(h.name) = 'user-agent'), h -> h.value), 1), '-')
            ORDER BY request_count DESC
            LIMIT {limit}";
    }

    private static string GetCell(List<Datum> cols, int index)
        => index < cols.Count && cols[index].VarCharValue != null ? cols[index].VarCharValue : string.Empty;
}