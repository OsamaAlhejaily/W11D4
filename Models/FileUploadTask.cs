using System.Collections.Concurrent;

public class FileUploadTask
{
    public string ProcessingId { get; set; }
    public byte[] FileContent { get; set; }
    public string OriginalFileName { get; set; }
    public bool SimulateScan { get; set; }
    public int ScanDelayMs { get; set; }
    public string StoragePath { get; set; }
    
}