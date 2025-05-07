using System.Collections.Concurrent;
using System.Threading.Channels;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddSingleton(Channel.CreateUnbounded<FileUploadTask>());//: Registers a shared queue for asynchronously handling file upload tasks.
builder.Services.AddSingleton<ConcurrentDictionary<string, string>>(UploadStatusTracker.StatusMap);// Registers a shared dictionary to track the status of each file upload.
builder.Services.AddHostedService<FileProcessingService>();//Starts a background service that processes uploaded files from the queue.

var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI();

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseAuthorization();

app.MapControllers();

app.Run();

