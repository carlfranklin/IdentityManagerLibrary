namespace IdentityManagerLibrary
{
    /// <summary>
    /// General response object.
    /// </summary>    
    public class Response
    {
        public bool Success { get; internal set; } = false;
        public string Messages { get; internal set; } = string.Empty;
    }
}