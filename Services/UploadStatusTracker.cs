using System.Collections.Concurrent;

public static class UploadStatusTracker
{
    public static ConcurrentDictionary<string, string> StatusMap { get; } = new();
}