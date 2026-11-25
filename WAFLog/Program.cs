using Amazon.Athena;
using Microsoft.AspNetCore.HttpOverrides;
using WAFLog.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

// Register AWS Athena SDK (reads AWS:Region from appsettings.json; uses EC2 IAM Role in prod)
builder.Services.AddDefaultAWSOptions(builder.Configuration.GetAWSOptions());
builder.Services.AddAWSService<IAmazonAthena>();

// Register Athena & Gemini Services
builder.Services.AddScoped<IAthenaQueryService, AthenaQueryService>();
builder.Services.AddScoped<IGeminiWafAnalyzerService, GeminiWafAnalyzerService>();

// Read allowed CORS origins from configuration instead of hardcoding localhost
var allowedOrigins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>()
    ?? new[] { "http://localhost:3000", "http://localhost:3001" };

builder.Services.AddCors(options =>
{
    options.AddPolicy("NextJsPolicy", policy =>
    {
        policy.WithOrigins(allowedOrigins)
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});

// Support Nginx / ALB reverse proxy headers on Linux
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    // Clear default loopback-only restriction so internal VPC ALB / Nginx IPs are trusted
    options.KnownNetworks.Clear();
    options.KnownProxies.Clear();
});

var app = builder.Build();

app.UseForwardedHeaders();

// Only redirect HTTP -> HTTPS when not running behind an internal HTTP reverse proxy/VPC link
if (!app.Environment.IsProduction())
{
    app.UseHttpsRedirection();
}

app.UseCors("NextJsPolicy");
app.UseAuthorization();
app.MapControllers();

app.Run();