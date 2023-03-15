namespace ysoserial.Helpers.SurrogateClasses
{
    /// <summary>
    /// Surrogate class for bait-and-switch version of ObjectDataProvider.
    /// </summary>
    internal sealed class ObjectDataProviderSurrogate
    {
        public string MethodName { get; set; }
        public object ObjectInstance { get; set; }
    }

    /// <summary>
    /// Surrogate class for bait-and-switch version of ProcessStartInfo.
    /// </summary>
    internal sealed class ProcessStartInfoSurrogate
    {
        public string FileName { get; set; }
        public string Arguments { get; set; }
    }

    /// <summary>
    /// Surrogate class for bait-and-switch version of Process.
    /// </summary>
    internal sealed class ProcessSurrogate
    {
        public ProcessStartInfoSurrogate StartInfo { get; set; }
    }
}
