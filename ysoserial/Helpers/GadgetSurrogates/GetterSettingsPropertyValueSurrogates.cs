namespace ysoserial.Helpers.SurrogateClasses
{
    /// <summary>
    /// Surrogate class for bait-and-switch version of SettingsPropertyValue.
    /// </summary>
    internal sealed class SettingsPropertyValueSurrogate
    {
        public bool Deserialized { get; set; }
        public object SerializedValue { get; set; }
        public object property { get; set; }

    }

    /// <summary>
    /// Surrogate class for bait-and-switch version of PropertyGrid.
    /// </summary>
    internal sealed class PropertyGridSurrogate
    {
        public object[] SelectedObjects { get; set; }
    }
}
