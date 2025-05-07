using Microsoft.AspNetCore.Mvc;
using System.Collections.Concurrent;
using System.Threading.Channels;
using System.IO;

[ApiController]
[Route("[controller]")]
public class UploadController : ControllerBase
{
    private readonly Channel<FileUploadTask> _uploadChannel;
    private readonly IConfiguration _config;
    private readonly IWebHostEnvironment _env;
    private readonly ConcurrentDictionary<string, string> _statusMap;
    private readonly ILogger<UploadController> _logger;

    public UploadController(Channel<FileUploadTask> uploadChannel, IConfiguration config,
                            IWebHostEnvironment env, ConcurrentDictionary<string, string> statusMap,
                            ILogger<UploadController> logger)
    {
        _uploadChannel = uploadChannel;
        _config = config;
        _env = env;
        _statusMap = statusMap;
        _logger = logger;
    }

    [HttpPost("upload")]
    public async Task<IActionResult> Upload(IFormFile file)
    {
        if (file == null || file.Length == 0)
            return BadRequest("No file uploaded.");

        if (file.Length > 10 * 1024 * 1024)
            return BadRequest("File too large. Maximum size is 10MB.");

        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        if (IsRateLimitExceeded(ip))
            return StatusCode(429, "Rate limit exceeded. Please try again later.");

        if (IsExecutableFile(file))
            return BadRequest("Executable files are not allowed.");

        var id = Guid.NewGuid().ToString();

        var sanitizedFileName = SanitizeFileName(file.FileName);

        try
        {
            using var memoryStream = new MemoryStream();
            await file.CopyToAsync(memoryStream);
            byte[] fileContent = memoryStream.ToArray();

            _statusMap[id] = "Pending";

            bool simulateScan = _config.GetValue<bool>("FileUpload:SimulateAntivirusScan", true);
            int scanDelayMs = _config.GetValue<int>("FileUpload:ScanDelayMilliseconds", 3000);

            string storagePath = Path.Combine(_env.WebRootPath, "uploads");
            if (!Directory.Exists(storagePath))
            {
                Directory.CreateDirectory(storagePath);
            }

            await _uploadChannel.Writer.WriteAsync(new FileUploadTask
            {
                ProcessingId = id,
                FileContent = fileContent,
                OriginalFileName = sanitizedFileName,
                SimulateScan = simulateScan,
                ScanDelayMs = scanDelayMs,
                StoragePath = storagePath
            });

            _logger.LogInformation("File {FileName} queued for processing with ID: {Id}", sanitizedFileName, id);
            return Ok(new { processingId = id });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during file upload for {FileName}", file.FileName);
            return StatusCode(500, "An error occurred while processing your upload.");
        }
    }

    [HttpGet("status/{id}")]
    public IActionResult Status(string id)
    {
        if (!_statusMap.TryGetValue(id, out var status))
            return NotFound("Invalid processing ID");

        return Ok(new { status });
    }

    private static readonly Dictionary<string, List<DateTime>> UploadLog = new();

    private bool IsRateLimitExceeded(string ip, int maxUploads = 5, int intervalSeconds = 60)
    {
        lock (UploadLog)
        {
            if (!UploadLog.ContainsKey(ip))
                UploadLog[ip] = new List<DateTime>();

            var cutoffTime = DateTime.UtcNow.AddSeconds(-intervalSeconds);
            UploadLog[ip].RemoveAll(time => time < cutoffTime);

            if (UploadLog[ip].Count >= maxUploads)
                return true;

            UploadLog[ip].Add(DateTime.UtcNow);
            return false;
        }
    }

    private bool IsExecutableFile(IFormFile file)
    {
        using (var stream = file.OpenReadStream())
        using (var reader = new BinaryReader(stream))
        {
            if (stream.Length >= 2)
            {
                var headerBytes = reader.ReadBytes(4);
                if (headerBytes.Length >= 2 && headerBytes[0] == 0x4D && headerBytes[1] == 0x5A)
                    return true;
            }
        }

        file.OpenReadStream().Position = 0;

        string ext = Path.GetExtension(file.FileName).ToLowerInvariant();
        string[] disallowedExts = { ".exe", ".dll", ".bat", ".cmd", ".msi", ".ps1", ".sh", ".jar" };

        return disallowedExts.Contains(ext);
    }

    private string SanitizeFileName(string fileName)
    {
        if (string.IsNullOrEmpty(fileName))
            return "unnamed_file";

        string sanitized = fileName
            .Replace("..", "")
            .Replace("//", "")
            .Replace("\\", "")
            .Replace(":", "")
            .Replace("%", "")
            .Replace("&", "")
            .Replace("<", "")
            .Replace(">", "")
            .Replace("$", "")
            .Replace("#", "")
            .Replace("*", "")
            .Replace("?", "")
            .Replace("|", "")
            .Replace("\"", "")
            .Replace("'", "");

        if (string.IsNullOrWhiteSpace(sanitized))
            return "unnamed_file";

        return sanitized;
    }
}