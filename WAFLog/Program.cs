using Amazon.Athena;
using WAFLog.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

// Register AWS Athena SDK (reads AWS:Region from appsettings.json; uses EC2 IAM Role in prod)
builder.Services.AddDefaultAWSOptions(builder.Configuration.GetAWSOptions());
builder.Services.AddAWSService<IAmazonAthena>();

// Register Athena Query Service
builder.Services.AddScoped<IAthenaQueryService, AthenaQueryService>();

// Allow Next.js frontend server
builder.Services.AddCors(options =>
{
    options.AddPolicy("NextJsPolicy", policy =>
    {
        policy.WithOrigins("http://localhost:3000") // Add your internal Next.js server URL here later
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});

var app = builder.Build();

app.UseHttpsRedirection();
app.UseCors("NextJsPolicy");
app.UseAuthorization();
app.MapControllers();

app.Run();