﻿using System.Text;
using System.Text.Encodings.Web;

namespace Bit.BlazorUI;

/// <summary>
/// BitFileUpload component wraps the HTML file input element(s) and uploads them to a given URL. The files can be removed by specifying the URL they have been uploaded.
/// </summary>
public partial class BitFileUpload : BitComponentBase
{
    private const int MIN_CHUNK_SIZE = 512 * 1024; // 512 kb
    private const int MAX_CHUNK_SIZE = 10 * 1024 * 1024; // 10 mb



    private ElementReference _inputRef;
    private List<BitFileInfo> _files = [];
    private long _internalChunkSize = MIN_CHUNK_SIZE;
    private IJSObjectReference _dropZoneRef = default!;
    private DotNetObjectReference<BitFileUpload> _dotnetObj = default!;



    [Inject] private IJSRuntime _js { get; set; } = default!;

    [Inject] private HttpClient _httpClient { get; set; } = default!;



    /// <summary>
    /// The value of the accept attribute of the input element.
    /// </summary>
    [Parameter] public string? Accept { get; set; }

    /// <summary>
    /// Filters files by extension.
    /// </summary>
    [Parameter] public IReadOnlyCollection<string> AllowedExtensions { get; set; } = ["*"];

    /// <summary>
    /// Enables the append mode that appends any additional selected file(s) to the current file list.
    /// </summary>
    [Parameter] public bool Append { get; set; }

    /// <summary>
    /// Calculate the chunk size dynamically based on the user's Internet speed between 512 KB and 10 MB.
    /// </summary>
    [Parameter] public bool AutoChunkSize { get; set; }

    /// <summary>
    /// Automatically resets the file-upload before starting to browse for files.
    /// </summary>
    [Parameter] public bool AutoReset { get; set; }

    /// <summary>
    /// Automatically starts the upload file(s) process immediately after selecting the file(s).
    /// </summary>
    [Parameter] public bool AutoUpload { get; set; }

    /// <summary>
    /// Enables the chunked upload.
    /// </summary>
    [Parameter] public bool ChunkedUpload { get; set; }

    /// <summary>
    /// The size of each chunk of file upload in bytes.
    /// </summary>
    [Parameter]
    [CallOnSet(nameof(OnSetChunkSize))]
    public long? ChunkSize { get; set; }

    /// <summary>
    /// The message shown for failed file removes.
    /// </summary>
    [Parameter] public string FailedRemoveMessage { get; set; } = "File remove failed";

    /// <summary>
    /// The message shown for failed file uploads.
    /// </summary>
    [Parameter] public string FailedUploadMessage { get; set; } = "File upload failed";

    /// <summary>
    /// Hides the file view section of the file upload.
    /// </summary>
    [Parameter] public bool HideFileView { get; set; }

    /// <summary>
    /// The text of select file button.
    /// </summary>
    [Parameter] public string Label { get; set; } = "Browse";

    /// <summary>
    /// A custom razor template for select button.
    /// </summary>
    [Parameter] public RenderFragment? LabelTemplate { get; set; }

    /// <summary>
    /// Specifies the maximum size (byte) of the file (0 for unlimited).
    /// </summary>
    [Parameter] public long MaxSize { get; set; }

    /// <summary>
    /// Specifies the message for the failed uploading progress due to exceeding the maximum size.
    /// </summary>
    [Parameter] public string MaxSizeErrorMessage { get; set; } = "The file size is larger than the max size";

    /// <summary>
    /// Enables multi-file selection.
    /// </summary>
    [Parameter] public bool Multiple { get; set; }

    /// <summary>
    /// Specifies the message for the failed uploading progress due to the allowed extensions.
    /// </summary>
    [Parameter] public string NotAllowedExtensionErrorMessage { get; set; } = "The file type is not allowed";

    /// <summary>
    /// Callback for when all files are uploaded.
    /// </summary>
    [Parameter] public EventCallback<BitFileInfo[]> OnAllUploadsComplete { get; set; }

    /// <summary>
    /// Callback for when file or files status change.
    /// </summary>
    [Parameter] public EventCallback<BitFileInfo[]> OnChange { get; set; }

    /// <summary>
    /// Callback for when the file upload is progressed.
    /// </summary>
    [Parameter] public EventCallback<BitFileInfo> OnProgress { get; set; }

    /// <summary>
    /// Callback for when a remove file is done.
    /// </summary>
    [Parameter] public EventCallback<BitFileInfo> OnRemoveComplete { get; set; }

    /// <summary>
    /// Callback for when a remove file is failed.
    /// </summary>
    [Parameter] public EventCallback<BitFileInfo> OnRemoveFailed { get; set; }

    /// <summary>
    /// Callback for when a file upload is about to start.
    /// </summary>
    [Parameter] public EventCallback<BitFileInfo> OnUploading { get; set; }

    /// <summary>
    /// Callback for when a file upload is done.
    /// </summary>
    [Parameter] public EventCallback<BitFileInfo> OnUploadComplete { get; set; }

    /// <summary>
    /// Callback for when an upload file is failed.
    /// </summary>
    [Parameter] public EventCallback<BitFileInfo> OnUploadFailed { get; set; }

    /// <summary>
    /// Custom http headers for remove request.
    /// </summary>
    [Parameter] public Dictionary<string, string>? RemoveRequestHttpHeaders { get; set; }

    /// <summary>
    /// The provider function to create the http headers for remove request.
    /// </summary>
    [Parameter] public Func<Task<Dictionary<string, string>>>? RemoveRequestHttpHeadersProvider { get; set; }

    /// <summary>
    /// Custom query strings for remove request.
    /// </summary>
    [Parameter] public Dictionary<string, string>? RemoveRequestQueryStrings { get; set; }

    /// <summary>
    /// The provider function to create the query strings for remove request.
    /// </summary>
    [Parameter] public Func<Task<Dictionary<string, string>>>? RemoveRequestQueryStringsProvider { get; set; }

    /// <summary>
    /// URL of the server endpoint removing the files.
    /// </summary>
    [Parameter] public string? RemoveUrl { get; set; }

    /// <summary>
    /// Show/Hide after upload remove button.
    /// </summary>
    [Parameter] public bool ShowRemoveButton { get; set; }

    /// <summary>
    /// The message shown for successful file uploads.
    /// </summary>
    [Parameter] public string SuccessfulUploadMessage { get; set; } = "File upload succeed";

    /// <summary>
    /// Custom http headers for upload request.
    /// </summary>
    [Parameter] public Dictionary<string, string>? UploadRequestHttpHeaders { get; set; }

    /// <summary>
    /// The provider function to create the http headers for upload request.
    /// </summary>
    [Parameter] public Func<Task<Dictionary<string, string>>>? UploadRequestHttpHeadersProvider { get; set; }

    /// <summary>
    /// Custom query strings for upload request.
    /// </summary>
    [Parameter] public Dictionary<string, string>? UploadRequestQueryStrings { get; set; }

    /// <summary>
    /// The provider function to create the query strings for upload request.
    /// </summary>
    [Parameter] public Func<Task<Dictionary<string, string>>>? UploadRequestQueryStringsProvider { get; set; }

    /// <summary>
    /// URL of the server endpoint receiving the files.
    /// </summary>
    [Parameter] public string? UploadUrl { get; set; }

    /// <summary>
    /// The provider function to create the URL of the server endpoint receiving the files.
    /// </summary>
    [Parameter] public Func<Task<string?>>? UploadUrlProvider { get; set; }

    /// <summary>
    /// The custom file view template.
    /// </summary>
    [Parameter] public RenderFragment<BitFileInfo>? FileViewTemplate { get; set; }



    /// <summary>
    /// A list of all of the selected files to upload.
    /// </summary>
    public IReadOnlyList<BitFileInfo> Files => _files;

    /// <summary>
    /// The current status of the file uploader.
    /// </summary>
    public BitFileUploadStatus UploadStatus { get; private set; }

    /// <summary>
    /// The id of the file input element.
    /// </summary>
    public string? InputId { get; private set; }

    /// <summary>
    /// Indicates that the file upload is in the middle of removing a file.
    /// </summary>
    public bool IsRemoving { get; private set; }

    /// <summary>
    /// Starts uploading the file(s).
    /// </summary>
    public async Task Upload(BitFileInfo? fileInfo = null, string? uploadUrl = null)
    {
        if (_files.Any() is false) return;

        if (UploadStatus != BitFileUploadStatus.InProgress)
        {
            UploadStatus = BitFileUploadStatus.InProgress;
        }

        await UpdateStatus(BitFileUploadStatus.InProgress, fileInfo);

        if (fileInfo is null)
        {
            foreach (var file in _files)
            {
                await UploadOneFile(file, uploadUrl);
            }
        }
        else
        {
            await UploadOneFile(fileInfo, uploadUrl);
        }
    }

    /// <summary>
    /// Pauses the upload.
    /// </summary>
    /// <param name="fileInfo">
    /// null (default) => all files | else => specific file
    /// </param>
    public void PauseUpload(BitFileInfo? fileInfo = null)
    {
        if (_files.Any() is false) return;

        if (fileInfo is null)
        {
            foreach (var file in _files)
            {
                file.PauseUploadRequested = true;
            }
        }
        else
        {
            fileInfo.PauseUploadRequested = true;
        }
    }

    /// <summary>
    /// Cancels the upload.
    /// </summary>
    /// <param name="fileInfo">
    /// null (default) => all files | else => specific file
    /// </param>
    public void CancelUpload(BitFileInfo? fileInfo = null)
    {
        if (_files.Any() is false) return;

        if (fileInfo is null)
        {
            foreach (var file in _files)
            {
                file.CancelUploadRequested = true;
            }
        }
        else
        {
            fileInfo.CancelUploadRequested = true;
        }
    }

    /// <summary>
    /// Removes a file by calling the RemoveUrl if the file upload is already started.
    /// </summary>
    /// <param name="fileInfo">
    /// null => all files | else => specific file
    /// </param>
    public async Task RemoveFile(BitFileInfo? fileInfo = null)
    {
        if (_files.Any() is false) return;
        if (IsRemoving) return;

        IsRemoving = true;

        if (fileInfo is null)
        {
            foreach (var file in _files)
            {
                await RemoveOneFile(file);
            }
        }
        else
        {
            await RemoveOneFile(fileInfo);
        }

        IsRemoving = false;
    }

    /// <summary>
    /// Opens a file selection dialog.
    /// </summary>
    public async Task Browse()
    {
        if (IsEnabled is false) return;

        if (AutoReset)
        {
            await Reset();
        }

        await _js.BitFileUploadBrowse(_inputRef);
    }

    /// <summary>
    /// Resets the file upload.
    /// </summary>
    public async Task Reset()
    {
        _files.Clear();
        await _js.BitFileUploadReset(UniqueId, _inputRef);
    }



    /// <summary>
    /// Receive upload progress notification from underlying JavaScript.
    /// </summary>
    [JSInvokable("HandleChunkUploadProgress")]
    public async Task __HandleChunkUploadProgress(int index, long loaded)
    {
        if (_files.Any() is false) return;

        var file = _files[index];
        if (file.Status != BitFileUploadStatus.InProgress) return;

        file.LastChunkUploadedSize = loaded;
        await UpdateStatus(BitFileUploadStatus.InProgress, file);
        StateHasChanged();
    }

    /// <summary>
    /// Receive upload finished notification from underlying JavaScript.
    /// </summary>
    [JSInvokable("HandleChunkUpload")]
    public async Task __HandleChunkUpload(int fileIndex, int responseStatus, string responseText)
    {
        if (_files.Any() is false || UploadStatus == BitFileUploadStatus.Paused) return;

        var file = _files[fileIndex];
        if (file.Status != BitFileUploadStatus.InProgress) return;

        file.TotalUploadedSize += ChunkedUpload ? _internalChunkSize : file.Size;
        file.LastChunkUploadedSize = 0;

        UpdateChunkSize(fileIndex);

        if (file.TotalUploadedSize < file.Size)
        {
            await Upload(file);
        }
        else
        {
            file.Message = responseText;
            if (responseStatus is >= 200 and <= 299)
            {
                await UpdateStatus(BitFileUploadStatus.Completed, file);
            }
            else if ((responseStatus is 0 && (file.Status is BitFileUploadStatus.Paused or BitFileUploadStatus.Canceled)) is false)
            {
                await UpdateStatus(BitFileUploadStatus.Failed, file);
            }

            var allFilesUploaded = _files.All(c => c.Status is BitFileUploadStatus.Completed or BitFileUploadStatus.Failed);
            if (allFilesUploaded)
            {
                UploadStatus = BitFileUploadStatus.Completed;
                await OnAllUploadsComplete.InvokeAsync([.. _files]);
            }
        }

        StateHasChanged();
    }



    protected override string RootElementClass => "bit-upl";

    protected override Task OnInitializedAsync()
    {
        InputId = $"FileUpload-{UniqueId}-input";

        return base.OnInitializedAsync();
    }

    protected override async Task OnAfterRenderAsync(bool firstRender)
    {
        if (firstRender is false) return;

        _dotnetObj = DotNetObjectReference.Create(this);

        _dropZoneRef = await _js.BitFileUploadSetupDragDrop(RootElement, _inputRef);
    }



    internal bool IsFileTypeNotAllowed(BitFileInfo file)
    {
        if (Accept.HasNoValue()) return false;

        var fileSections = file.Name.Split('.');
        var extension = $".{fileSections?.Last()}";
        return AllowedExtensions.Count > 0 && AllowedExtensions.All(ext => ext != "*") && AllowedExtensions.All(ext => ext != extension);
    }

    private async Task HandleOnChange()
    {
        var uploadUrl = UploadUrl;
        if (UploadUrlProvider is not null)
        {
            uploadUrl = await UploadUrlProvider.Invoke();
        }

        var qs = UploadRequestQueryStrings;
        if (UploadRequestQueryStringsProvider is not null)
        {
            qs = await UploadRequestQueryStringsProvider.Invoke();
        }

        var url = qs is null ? uploadUrl : AddQueryString(uploadUrl, qs);

        if (Append is false)
        {
            _files.Clear();
        }

        if (IsDisposed) return;

        var httpHeaders = UploadRequestHttpHeadersProvider is null ? UploadRequestHttpHeaders : (await UploadRequestHttpHeadersProvider.Invoke());

        _files.AddRange(await _js.BitFileUploadSetup(UniqueId, _dotnetObj, _inputRef, Append, url, httpHeaders));

        if (_files.Any() is false) return;

        await OnChange.InvokeAsync([.. _files]);

        if (AutoUpload)
        {
            await Upload();
        }
    }

    private async Task UploadOneFile(BitFileInfo fileInfo, string? uploadUrl = null)
    {
        if (_files.Any() is false || fileInfo.Status == BitFileUploadStatus.NotAllowed) return;

        var uploadedSize = fileInfo.TotalUploadedSize;
        if (fileInfo.Size != 0 && uploadedSize >= fileInfo.Size) return;

        if (MaxSize > 0 && fileInfo.Size > MaxSize)
        {
            await UpdateStatus(BitFileUploadStatus.NotAllowed, fileInfo);
            return;
        }

        if (IsFileTypeNotAllowed(fileInfo))
        {
            await UpdateStatus(BitFileUploadStatus.NotAllowed, fileInfo);
            return;
        }

        if (fileInfo.PauseUploadRequested)
        {
            await PauseUploadOneFile(fileInfo.Index);
            return;
        }

        if (fileInfo.CancelUploadRequested)
        {
            await CancelUploadOneFile(fileInfo.Index);
            return;
        }

        long to;
        long from = 0;
        if (ChunkedUpload)
        {
            from = fileInfo.TotalUploadedSize;
            if (fileInfo.Size > _internalChunkSize)
            {
                to = from + _internalChunkSize;
            }
            else
            {
                to = fileInfo.Size;
            }

            fileInfo.StartTimeUpload = DateTime.UtcNow;
            fileInfo.LastChunkUploadedSize = 0;
        }
        else
        {
            to = fileInfo.Size;
        }

        if (from == 0)
        {
            await OnUploading.InvokeAsync(fileInfo);
        }

        await _js.BitFileUploadUpload(UniqueId, from, to, fileInfo.Index, uploadUrl, fileInfo.HttpHeaders);
    }

    private async Task PauseUploadOneFile(int index)
    {
        if (_files.Any() is false) return;

        await _js.BitFileUploadPause(UniqueId, index);
        var file = _files[index];
        await UpdateStatus(BitFileUploadStatus.Paused, file);
        file.PauseUploadRequested = false;
    }

    private void UpdateChunkSize(int fileIndex)
    {
        if (_files.Any() is false || AutoChunkSize is false) return;

        var dtNow = DateTime.UtcNow;
        var duration = (dtNow - _files[fileIndex].StartTimeUpload.GetValueOrDefault(dtNow)).TotalMilliseconds;

        if (duration is >= 1000 and <= 1500) return;

        _internalChunkSize = Convert.ToInt64(_internalChunkSize / (duration / 1000));

        if (_internalChunkSize > MAX_CHUNK_SIZE)
        {
            _internalChunkSize = MAX_CHUNK_SIZE;
        }

        if (_internalChunkSize < MIN_CHUNK_SIZE)
        {
            _internalChunkSize = MIN_CHUNK_SIZE;
        }
    }

    private async Task UpdateStatus(BitFileUploadStatus uploadStatus, BitFileInfo? fileInfo = null)
    {
        if (_files.Any() is false) return;

        if (fileInfo is null)
        {
            UploadStatus = uploadStatus;

            var files = _files.Where(c => c.Status != BitFileUploadStatus.NotAllowed).ToArray();
            foreach (var file in files)
            {
                file.Status = uploadStatus;
            }

            await OnChange.InvokeAsync(files);
        }
        else
        {
            if (fileInfo.Status != uploadStatus)
            {
                fileInfo.Status = uploadStatus;
                await OnChange.InvokeAsync([fileInfo]);
            }

            switch (uploadStatus)
            {
                case BitFileUploadStatus.InProgress:
                    await OnProgress.InvokeAsync(fileInfo);
                    break;

                case BitFileUploadStatus.Completed:
                    await OnUploadComplete.InvokeAsync(fileInfo);
                    break;

                case BitFileUploadStatus.Failed:
                    await OnUploadFailed.InvokeAsync(fileInfo);
                    break;

                case BitFileUploadStatus.Removed:
                    await OnRemoveComplete.InvokeAsync(fileInfo);
                    break;

                case BitFileUploadStatus.RemoveFailed:
                    await OnRemoveFailed.InvokeAsync(fileInfo);
                    break;
            }
        }
    }

    private async Task CancelUploadOneFile(int index)
    {
        if (_files.Any() is false) return;

        await _js.BitFileUploadPause(UniqueId, index);
        var file = _files[index];
        await UpdateStatus(BitFileUploadStatus.Canceled, file);
        file.CancelUploadRequested = false;
    }

    private async Task RemoveOneFile(BitFileInfo fileInfo)
    {
        if (fileInfo.Status is BitFileUploadStatus.Removed) return;

        if (fileInfo.TotalUploadedSize > 0)
        {
            await RemoveOneFileFromServer(fileInfo);
        }
        else
        {
            await UpdateStatus(BitFileUploadStatus.Removed, fileInfo);
        }
    }

    private async Task RemoveOneFileFromServer(BitFileInfo fileInfo)
    {
        if (RemoveUrl.HasNoValue()) return;

        try
        {
            var url = AddQueryString(RemoveUrl!, "fileName", fileInfo.Name);

            var qs = RemoveRequestQueryStringsProvider is null
                        ? RemoveRequestQueryStrings
                        : (await RemoveRequestQueryStringsProvider.Invoke());

            if (qs is not null)
            {
                url = AddQueryString(url, qs);
            }

            using var request = new HttpRequestMessage(HttpMethod.Delete, url);

            request.Headers.Add("BIT_FILE_ID", fileInfo.FileId);

            var httpHeaders = (RemoveRequestHttpHeadersProvider is null
                                ? RemoveRequestHttpHeaders
                                : (await RemoveRequestHttpHeadersProvider.Invoke())) ?? [];

            foreach (var header in httpHeaders)
            {
                request.Headers.Add(header.Key, header.Value);
            }

            await _httpClient.SendAsync(request);

            await UpdateStatus(BitFileUploadStatus.Removed, fileInfo);
        }
        catch (Exception ex)
        {
            fileInfo.Message = ex.ToString();
            await UpdateStatus(BitFileUploadStatus.RemoveFailed, fileInfo);
        }
    }

    private static string AddQueryString(string uri, string name, string value)
    {
        return AddQueryString(uri, new Dictionary<string, string> { { name, value } });
    }

    private static string AddQueryString(string? url, Dictionary<string, string> queryStrings)
    {
        if (url.HasNoValue()) return string.Empty;

        // this method is copied from:
        // https://github.com/aspnet/HttpAbstractions/blob/master/src/Microsoft.AspNetCore.WebUtilities/QueryHelpers.cs

        int anchorIndex = url!.IndexOf('#', StringComparison.InvariantCultureIgnoreCase);
        string uriToBeAppended = url;
        string? anchorText = null;

        // If there is an anchor, then the query string must be inserted before its first occurrence.
        if (anchorIndex != -1)
        {
            anchorText = url[anchorIndex..];
            uriToBeAppended = url[..anchorIndex];
        }

        var queryIndex = uriToBeAppended.IndexOf('?', StringComparison.InvariantCultureIgnoreCase);
        var hasQuery = queryIndex != -1;

        var sb = new StringBuilder(uriToBeAppended);

        foreach (var parameter in queryStrings)
        {
            sb.Append(hasQuery ? '&' : '?');
            sb.Append(UrlEncoder.Default.Encode(parameter.Key));
            sb.Append('=');
            sb.Append(UrlEncoder.Default.Encode(parameter.Value));
            hasQuery = true;
        }

        sb.Append(anchorText);
        return sb.ToString();
    }

    private void OnSetChunkSize()
    {
        _internalChunkSize = ChunkSize.HasValue is false || AutoChunkSize
                                ? MIN_CHUNK_SIZE
                                : ChunkSize.Value;
    }



    protected override async ValueTask DisposeAsync(bool disposing)
    {
        if (IsDisposed || disposing is false) return;

        await base.DisposeAsync(disposing);

        if (_dropZoneRef is not null)
        {
            try
            {
                await _dropZoneRef.InvokeVoidAsync("dispose");
                await _dropZoneRef.DisposeAsync();
            }
            catch (JSDisconnectedException) { } // we can ignore this exception here
            catch (JSException ex)
            {
                // it seems it's safe to just ignore this exception here.
                // otherwise it will blow up the MAUI app in a page refresh for example.
                Console.WriteLine(ex.Message);
            }
        }

        if (_dotnetObj is not null)
        {
            _dotnetObj.Dispose();

            try
            {
                await _js.BitFileUploadClear(UniqueId);
            }
            catch (JSDisconnectedException) { } // we can ignore this exception here
        }
    }
}
