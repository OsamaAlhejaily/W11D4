using System.Threading.Channels;
using System.Collections.Concurrent;
using System.IO;
using System.Threading;

public class FileProcessingService : BackgroundService
{
    private readonly Channel<FileUploadTask> _uploadChannel;
    private readonly ILogger<FileProcessingService> _logger;
    private readonly IConfiguration _configuration;

    public FileProcessingService(
        Channel<FileUploadTask> uploadChannel,
        ILogger<FileProcessingService> logger,
        IConfiguration configuration)
    {
        _uploadChannel = uploadChannel;
        _logger = logger;
        _configuration = configuration;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("File Processing Service started");

        await foreach (var task in _uploadChannel.Reader.ReadAllAsync(stoppingToken))
        {
            try
            {
                _logger.LogInformation("Processing file: {FileName} with ID: {Id}",
                    task.OriginalFileName, task.ProcessingId);

                
                UploadStatusTracker.StatusMap[task.ProcessingId] = "Scanning";

                
                if (task.SimulateScan)
                {
                    _logger.LogInformation("Simulating antivirus scan for {FileName}", task.OriginalFileName);
                    await Task.Delay(task.ScanDelayMs, stoppingToken);
                }

              
                if (!IsFileHeaderValid(task.FileContent))
                {
                    _logger.LogWarning("Invalid file header detected for {FileName}", task.OriginalFileName);
                    UploadStatusTracker.StatusMap[task.ProcessingId] = "VirusDetected";
                    continue;
                }

                
                UploadStatusTracker.StatusMap[task.ProcessingId] = "Processing";

                
                Directory.CreateDirectory(task.StoragePath);

               
                string finalFileName = $"{Path.GetFileNameWithoutExtension(task.OriginalFileName)}_{DateTime.UtcNow.Ticks}{Path.GetExtension(task.OriginalFileName)}";
                string finalPath = Path.Combine(task.StoragePath, finalFileName);

                
                await File.WriteAllBytesAsync(finalPath, task.FileContent, stoppingToken);

                _logger.LogInformation("File {FileName} successfully saved to {Path}",
                    task.OriginalFileName, finalPath);

                
                UploadStatusTracker.StatusMap[task.ProcessingId] = "Completed";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to process file {FileName}", task.OriginalFileName);
                UploadStatusTracker.StatusMap[task.ProcessingId] = "Failed";
            }
        }
    }

    private bool IsFileHeaderValid(byte[] content)
    {
        
        if (content == null || content.Length < 4)
            return false;

      
        if (content.Length >= 5 &&
            content[0] == 0x25 && content[1] == 0x50 &&
            content[2] == 0x44 && content[3] == 0x46 &&
            content[4] == 0x2D)
            return true;

        if (content.Length >= 3 &&
            content[0] == 0xFF && content[1] == 0xD8 &&
            content[2] == 0xFF)
            return true;

        
        if (content.Length >= 4 &&
            content[0] == 0x89 && content[1] == 0x50 &&
            content[2] == 0x4E && content[3] == 0x47)
            return true;

        if (content.Length >= 6 &&
            content[0] == 0x47 && content[1] == 0x49 && content[2] == 0x46 &&
            content[3] == 0x38 && (content[4] == 0x37 || content[4] == 0x39) &&
            content[5] == 0x61)
            return true;

       
        if (content.Length >= 4 &&
            content[0] == 0x50 && content[1] == 0x4B &&
            content[2] == 0x03 && content[3] == 0x04)
            return true;

        
        int printableCount = 0;
        int sampleSize = Math.Min(100, content.Length);
        for (int i = 0; i < sampleSize; i++)
        {
            if (content[i] >= 32 && content[i] <= 126)
                printableCount++;
        }

        if ((double)printableCount / sampleSize > 0.8) 
            return true;

        
        return false;
    }
}