// ==++==
// 
//   Copyright (c) Microsoft Corporation.  All rights reserved.
// 
// ==--==
/*============================================================
 **
 ** Class: CommonBinaryClasses
 **
 **
 ** Purpose: utility classes
 **
 **
 ===========================================================*/


namespace ysoserial.Helpers.ModifiedVulnerableBinaryFormatters{

    using System;
    using System.IO;
    using System.Runtime.Serialization.Formatters;
    using System.Text;
    using System.Collections;
    using System.Reflection;
#if FEATURE_REMOTING    
    using System.Runtime.Remoting.Messaging;
#endif
    using System.Diagnostics;
    using System.Globalization;
    using System.Diagnostics.Contracts;
    using System.Runtime.Serialization;

    // Routines to convert between the runtime type and the type as it appears on the wire
    // modified internal -> public
    public static class BinaryConverter
    {

        // From the type create the BinaryTypeEnum and typeInformation which describes the type on the wire

        public static BinaryTypeEnum GetBinaryTypeInfo(Type type, WriteObjectInfo objectInfo, String typeName, ObjectWriter objectWriter, out Object typeInformation, out int assemId)
        {
            SerTrace.Log("BinaryConverter", "GetBinaryTypeInfo Entry type ",type,", typeName ",typeName," objectInfo "+objectInfo);     
            BinaryTypeEnum binaryTypeEnum;

            assemId = 0;
            typeInformation = null;

            if (Object.ReferenceEquals(type, Converter.typeofString))
                binaryTypeEnum = BinaryTypeEnum.String;
            else if (((objectInfo == null) || ((objectInfo != null) && !objectInfo.isSi))
                     && (Object.ReferenceEquals(type, Converter.typeofObject)))
            {
                // If objectInfo.Si then can be a surrogate which will change the type
                binaryTypeEnum = BinaryTypeEnum.Object;
            }
            else if (Object.ReferenceEquals(type, Converter.typeofStringArray))
                binaryTypeEnum = BinaryTypeEnum.StringArray;
            else if (Object.ReferenceEquals(type, Converter.typeofObjectArray))
                binaryTypeEnum = BinaryTypeEnum.ObjectArray;
            else if (Converter.IsPrimitiveArray(type, out typeInformation))
                binaryTypeEnum = BinaryTypeEnum.PrimitiveArray;
            else
            {
                InternalPrimitiveTypeE primitiveTypeEnum = objectWriter.ToCode(type);
                switch (primitiveTypeEnum)
                {
                    case InternalPrimitiveTypeE.Invalid:
                        String assembly = null;
                        if (objectInfo == null)
                        {
                            //assembly = type.Assembly.FullName;
                            //typeInformation = type.FullName;

                            typeInformation = BinaryFormatterMinifier.FullTypeNameMinifier(type.FullName, type.Assembly.FullName);
                            assembly = BinaryFormatterMinifier.AssemblyOrTypeNameMinifier(type.Assembly.FullName);
                        }
                        else
                        {
                            //assembly = objectInfo.GetAssemblyString();
                            //typeInformation = objectInfo.GetTypeFullName();

                            typeInformation = BinaryFormatterMinifier.FullTypeNameMinifier(objectInfo.GetTypeFullName(), objectInfo.GetAssemblyString());
                            assembly = BinaryFormatterMinifier.AssemblyOrTypeNameMinifier(objectInfo.GetAssemblyString());
                        }

                        //if (assembly.Equals(Converter.urtAssemblyString))
                        if (assembly.Equals(BinaryFormatterMinifier.AssemblyOrTypeNameMinifier(Converter.urtAssemblyString)))
                        {
                            binaryTypeEnum = BinaryTypeEnum.ObjectUrt;
                            assemId = 0;
                        }
                        else
                        {
                            binaryTypeEnum = BinaryTypeEnum.ObjectUser;
                            //Contract.Assert(objectInfo!=null, "[BinaryConverter.GetBinaryTypeInfo]objectInfo null for user object");
                            assemId = (int)objectInfo.assemId;
                            if (assemId == 0)
                                throw new SerializationException(Environment.GetResourceString("Serialization_AssemblyId",typeInformation));
                        }
                        break;
                    default:
                        binaryTypeEnum = BinaryTypeEnum.Primitive;
                        typeInformation = primitiveTypeEnum;
                        break;
                }
            }

            SerTrace.Log( "BinaryConverter", "GetBinaryTypeInfo Exit ",((Enum)binaryTypeEnum).ToString(),", typeInformation ",typeInformation," assemId ",assemId);             
            return binaryTypeEnum;
        }


        // Used for non Si types when Parsing
        public static BinaryTypeEnum GetParserBinaryTypeInfo(Type type, out Object typeInformation)
        {
            SerTrace.Log("BinaryConverter", "GetParserBinaryTypeInfo Entry type ",type);        
            BinaryTypeEnum binaryTypeEnum;
            typeInformation = null;

            if (Object.ReferenceEquals(type, Converter.typeofString))
                binaryTypeEnum = BinaryTypeEnum.String;
            else if (Object.ReferenceEquals(type, Converter.typeofObject))
                binaryTypeEnum = BinaryTypeEnum.Object;
            else if (Object.ReferenceEquals(type, Converter.typeofObjectArray))
                binaryTypeEnum = BinaryTypeEnum.ObjectArray;
            else if (Object.ReferenceEquals(type, Converter.typeofStringArray))
                binaryTypeEnum = BinaryTypeEnum.StringArray;
            else if (Converter.IsPrimitiveArray(type, out typeInformation))
                binaryTypeEnum = BinaryTypeEnum.PrimitiveArray;
            else
            {
                InternalPrimitiveTypeE primitiveTypeEnum = Converter.ToCode(type);
                switch (primitiveTypeEnum)
                {
                    case InternalPrimitiveTypeE.Invalid:
                        if (Assembly.GetAssembly(type) == Converter.urtAssembly)
                            binaryTypeEnum = BinaryTypeEnum.ObjectUrt;
                        else
                            binaryTypeEnum = BinaryTypeEnum.ObjectUser;

                        typeInformation = type.FullName;
                        break;
                    default:
                        binaryTypeEnum = BinaryTypeEnum.Primitive;
                        typeInformation = primitiveTypeEnum;
                        break;
                }
            }

            SerTrace.Log( "BinaryConverter", "GetParserBinaryTypeInfo Exit ",((Enum)binaryTypeEnum).ToString(),", typeInformation ",typeInformation);               
            return binaryTypeEnum;
        }

        // Writes the type information on the wire
        public static void WriteTypeInfo(BinaryTypeEnum binaryTypeEnum, Object typeInformation, int assemId, __BinaryWriter sout)
        {
            SerTrace.Log( "BinaryConverter", "WriteTypeInfo Entry  ",((Enum)binaryTypeEnum).ToString()," ",typeInformation," assemId ",assemId);
            
            switch (binaryTypeEnum)
            {
                case BinaryTypeEnum.Primitive:
                case BinaryTypeEnum.PrimitiveArray:
                    //Contract.Assert(typeInformation!=null, "[BinaryConverter.WriteTypeInfo]typeInformation!=null");
                    //sout.WriteByte((Byte)((InternalPrimitiveTypeE) typeInformation));
                    sout.WriteByte((Byte)((InternalPrimitiveTypeE) Convert.ToInt32(typeInformation)));                    
                    break;
                case BinaryTypeEnum.String:
                case BinaryTypeEnum.Object:
                case BinaryTypeEnum.StringArray:
                case BinaryTypeEnum.ObjectArray:
                    break;                    
                case BinaryTypeEnum.ObjectUrt:
                    //Contract.Assert(typeInformation!=null, "[BinaryConverter.WriteTypeInfo]typeInformation!=null");
                    sout.WriteString(typeInformation.ToString());
                    break;
                case BinaryTypeEnum.ObjectUser:                             
                    //Contract.Assert(typeInformation!=null, "[BinaryConverter.WriteTypeInfo]typeInformation!=null");
                    sout.WriteString(typeInformation.ToString());
                    sout.WriteInt32(assemId);
                    break;                    
                default:
                    throw new SerializationException(Environment.GetResourceString("Serialization_TypeWrite",((Enum)binaryTypeEnum).ToString()));
            }
            SerTrace.Log( "BinaryConverter", "WriteTypeInfo Exit");
        }

        // Reads the type information from the wire
        public static Object ReadTypeInfo(BinaryTypeEnum binaryTypeEnum, __BinaryParser input, out int assemId)
        {
            SerTrace.Log( "BinaryConverter", "ReadTypeInfo Entry  ",((Enum)binaryTypeEnum).ToString());
            Object var = null;
            int readAssemId = 0;

            switch (binaryTypeEnum)
            {
                case BinaryTypeEnum.Primitive:
                case BinaryTypeEnum.PrimitiveArray:
                    var = (InternalPrimitiveTypeE)input.ReadByte();
                    break;
                case BinaryTypeEnum.String:
                case BinaryTypeEnum.Object:
                case BinaryTypeEnum.StringArray:
                case BinaryTypeEnum.ObjectArray:
                    break;                    
                case BinaryTypeEnum.ObjectUrt:
                    var = input.ReadString();                   
                    break;
                case BinaryTypeEnum.ObjectUser:
                    var = input.ReadString();
                    readAssemId = input.ReadInt32();
                    break;                    
                default:
                    throw new SerializationException(Environment.GetResourceString("Serialization_TypeRead",((Enum)binaryTypeEnum).ToString()));                 
            }
            SerTrace.Log( "BinaryConverter", "ReadTypeInfo Exit  ",var," assemId ",readAssemId);
            assemId = readAssemId;
            return var;
        }

        // Given the wire type information, returns the actual type and additional information
        [System.Security.SecurityCritical]  // auto-generated
        public static void TypeFromInfo(BinaryTypeEnum binaryTypeEnum,
                                          Object typeInformation,
                                          ObjectReader objectReader,
                                          BinaryAssemblyInfo assemblyInfo,
                                          out InternalPrimitiveTypeE primitiveTypeEnum,
                                          out String typeString,
                                          out Type type,
                                          out bool isVariant)
        {
            SerTrace.Log( "BinaryConverter", "TypeFromInfo Entry  ",((Enum)binaryTypeEnum).ToString());

            isVariant = false;
            primitiveTypeEnum = InternalPrimitiveTypeE.Invalid;
            typeString = null;
            type = null;

            switch (binaryTypeEnum)
            {
                case BinaryTypeEnum.Primitive:
                    primitiveTypeEnum = (InternalPrimitiveTypeE)typeInformation;                    
                    typeString = Converter.ToComType(primitiveTypeEnum);
                    type = Converter.ToType(primitiveTypeEnum);
                    break;
                case BinaryTypeEnum.String:
                    //typeString = "System.String";
                    type = Converter.typeofString;
                    break;
                case BinaryTypeEnum.Object:
                    //typeString = "System.Object";
                    type = Converter.typeofObject;
                    isVariant = true; 
                    break;
                case BinaryTypeEnum.ObjectArray:
                    //typeString = "System.Object[]";
                    type = Converter.typeofObjectArray;
                    break;
                case BinaryTypeEnum.StringArray:
                    //typeString = "System.String[]";
                    type = Converter.typeofStringArray;
                    break;
                case BinaryTypeEnum.PrimitiveArray:
                    primitiveTypeEnum = (InternalPrimitiveTypeE)typeInformation;                    
                    type = Converter.ToArrayType(primitiveTypeEnum);
                    break;
                case BinaryTypeEnum.ObjectUser:
                case BinaryTypeEnum.ObjectUrt:
                    if (typeInformation != null)
                    {
                        typeString = typeInformation.ToString();
                        type = objectReader.GetType(assemblyInfo, typeString);
                        // Temporary for backward compatibility
                        if (Object.ReferenceEquals(type, Converter.typeofObject))
                            isVariant = true;
                    }
                    break;
                default:
                    throw new SerializationException(Environment.GetResourceString("Serialization_TypeRead",((Enum)binaryTypeEnum).ToString()));                                     
            }

#if _DEBUG
                SerTrace.Log( "BinaryConverter", "TypeFromInfo Exit  "
                          ,((Enum)primitiveTypeEnum).ToString(),",typeString ",Util.PString(typeString)
                          ,", type ",Util.PString(type),", isVariant ",isVariant);      
#endif

        }

#if _DEBUG                        
         // Used to write type type on the record dump
        public static String TypeInfoTraceString(Object typeInformation)
        {
            String traceString = null;
            if (typeInformation == null)
                traceString = "(Null)";
            else if (typeInformation is String)
                traceString = "(UTF)";
            else
                traceString = "(Byte)";
            return traceString;
        }
#endif

    }

    public static class IOUtil
    {
        public static bool FlagTest(MessageEnum flag, MessageEnum target)
        {
            if ((flag & target) == target)
                return true;
            else
                return false;
        }

        public static void WriteStringWithCode(String value, __BinaryWriter sout)
        {
            if (value == null)
                sout.WriteByte((Byte)InternalPrimitiveTypeE.Null);
            else
            {
                sout.WriteByte((Byte)InternalPrimitiveTypeE.String);
                sout.WriteString(value);
            }
        }

        public static void WriteWithCode(Type type, Object value, __BinaryWriter sout)
        {
            if ((object)type == null)
                sout.WriteByte((Byte)InternalPrimitiveTypeE.Null);
            else if (Object.ReferenceEquals(type, Converter.typeofString))
                WriteStringWithCode((String)value, sout);
            else
            {
                InternalPrimitiveTypeE code = Converter.ToCode(type);
                sout.WriteByte((Byte)code);
                sout.WriteValue(code, value);
            }
        }

        public static Object ReadWithCode(__BinaryParser input)
        {
             InternalPrimitiveTypeE code = (InternalPrimitiveTypeE)input.ReadByte();
             if (code == InternalPrimitiveTypeE.Null)
                 return null;
             else if (code == InternalPrimitiveTypeE.String)
                 return input.ReadString();
             else
                 return input.ReadValue(code);
        }

        public static Object[] ReadArgs(__BinaryParser input)
        {
            int length = input.ReadInt32();
            Object[] args = new Object[length];
            for (int i=0; i<length; i++)
                args[i] = ReadWithCode(input);
            return args;
        }

    }


    public static class BinaryUtil
    {
        [Conditional("_LOGGING")]                               
        public static void NVTraceI(String name, String value)
        {
            //if (BCLDebug.CheckEnabled("BINARY"))
                BCLDebug.Trace("BINARY", "  ",name, " = ", value);
        }

        // Traces an name value pair
        [Conditional("_LOGGING")]                                       
        public static void NVTraceI(String name, Object value)
        {
            //if (BCLDebug.CheckEnabled("BINARY"))
                BCLDebug.Trace("BINARY", "  ",name, " = ", value);
        }

    }


    // Interface for Binary Records.
    public interface IStreamable
    {
        [System.Security.SecurityCritical]
        void Read(__BinaryParser input);
        void Write(__BinaryWriter sout);
#if _DEBUG        
        void Dump();
#endif
    }

    [Serializable]
    public sealed class BinaryAssemblyInfo
    {
        public String assemblyString;
        public Assembly assembly;


        public BinaryAssemblyInfo(String assemblyString)
        {
            this.assemblyString = assemblyString;
        }

        public BinaryAssemblyInfo(String assemblyString, Assembly assembly)
        {
            this.assemblyString = assemblyString;
            this.assembly = assembly;
        }

        public Assembly GetAssembly()
        {
            if (assembly == null)
            {
                //assembly = FormatterServices.LoadAssemblyFromStringNoThrow(assemblyString);
                try
                {
                    assembly = Assembly.Load(assemblyString);
                }
                catch { }
                
                if (assembly == null)
                    throw new SerializationException(Environment.GetResourceString("Serialization_AssemblyNotFound",assemblyString));
            }
            return assembly;
        }
    }

    // The Following classes read and write the binary records
    [Serializable]
    public sealed class SerializationHeaderRecord : IStreamable
    {
        public Int32 binaryFormatterMajorVersion = 1;
        public Int32 binaryFormatterMinorVersion = 0;
        public BinaryHeaderEnum binaryHeaderEnum;
        public Int32 topId;
        public Int32 headerId;
        public Int32 majorVersion;
        public Int32 minorVersion;

        public SerializationHeaderRecord()
        {
        }

        public SerializationHeaderRecord(BinaryHeaderEnum binaryHeaderEnum, Int32 topId, Int32 headerId, Int32 majorVersion, Int32 minorVersion)
        {
            this.binaryHeaderEnum = binaryHeaderEnum;
            this.topId = topId;
            this.headerId = headerId;
            this.majorVersion = majorVersion;
            this.minorVersion = minorVersion;
        }

        public  void Write(__BinaryWriter sout)
        {
            majorVersion = binaryFormatterMajorVersion;
            minorVersion = binaryFormatterMinorVersion;
            sout.WriteByte((Byte)binaryHeaderEnum);
            sout.WriteInt32(topId);
            sout.WriteInt32(headerId);
            sout.WriteInt32(binaryFormatterMajorVersion);
            sout.WriteInt32(binaryFormatterMinorVersion);      
        }

        private static int GetInt32(byte [] buffer, int index)
        {
            return (int)(buffer[index] | buffer[index+1] << 8 | buffer[index+2] << 16 | buffer[index+3] << 24);
        }

        [System.Security.SecurityCritical] // implements Critical method
        public  void Read(__BinaryParser input)
        {
            byte [] headerBytes = input.ReadBytes(17);
            // Throw if we couldnt read header bytes
            if (headerBytes.Length < 17)
                //__Error.EndOfFile();
                throw new EndOfStreamException(Environment.GetResourceString("IO.EOF_ReadBeyondEOF"));

            majorVersion = GetInt32(headerBytes, 9);
            if (majorVersion > binaryFormatterMajorVersion)
                throw new SerializationException(Environment.GetResourceString("Serialization_InvalidFormat", BitConverter.ToString(headerBytes)));
            
            // binaryHeaderEnum has already been read
            binaryHeaderEnum = (BinaryHeaderEnum)headerBytes[0];
            topId = GetInt32(headerBytes, 1);
            headerId = GetInt32(headerBytes, 5);
            minorVersion = GetInt32(headerBytes, 13);
        }

        public  void Dump()
        {
            DumpInternal();
        }


        [Conditional("_LOGGING")]
        private void DumpInternal()
        {
            //if (BCLDebug.CheckEnabled("BINARY"))
            {
                BCLDebug.Trace("BINARY", "*****SerializationHeaderRecord*****");
                BinaryUtil.NVTraceI("binaryHeaderEnum (Byte)", ((Enum)binaryHeaderEnum).ToString());
                BinaryUtil.NVTraceI("topId (Int32)", topId);
                BinaryUtil.NVTraceI("headerId (Int32)", headerId);
                BinaryUtil.NVTraceI("majorVersion (Int32)", majorVersion);
                BinaryUtil.NVTraceI("minorVersion (Int32)", minorVersion);
                BCLDebug.Trace("BINARY","***********************************");
            }
        }
    }

    [Serializable]
    public sealed class BinaryAssembly : IStreamable
    {
        public Int32 assemId;
        public String assemblyString;

        public BinaryAssembly()
        {
        }


        public void Set(Int32 assemId, String assemblyString)
        {
            SerTrace.Log( this, "BinaryAssembly Set ",assemId," ",assemblyString);      
            this.assemId = assemId;
            this.assemblyString = assemblyString;
        }


        public void Write(__BinaryWriter sout)
        {
            sout.WriteByte((Byte)BinaryHeaderEnum.Assembly);
            sout.WriteInt32(assemId);
            sout.WriteString(assemblyString);
        }

        [System.Security.SecurityCritical] // implements Critical method
        public void Read(__BinaryParser input)
        {
            assemId = input.ReadInt32();
            assemblyString = input.ReadString();
        }

        public void Dump()
        {
            DumpInternal();
        }

        [Conditional("_LOGGING")]
        private void DumpInternal()
        {
            //if (BCLDebug.CheckEnabled("BINARY"))
            {
                BCLDebug.Trace("BINARY","*****BinaryAssembly*****");
                BinaryUtil.NVTraceI("binaryHeaderEnum (Byte)", "Assembly");
                BinaryUtil.NVTraceI("assemId (Int32)", assemId);        
                BinaryUtil.NVTraceI("Assembly (UTF)", assemblyString);
                BCLDebug.Trace("BINARY","****************************");
            }
        }
    }

    [Serializable]
    public sealed class BinaryCrossAppDomainAssembly : IStreamable
    {
        public Int32 assemId;
        public Int32 assemblyIndex;

        public BinaryCrossAppDomainAssembly()
        {
        }

        public void Write(__BinaryWriter sout)
        {
            sout.WriteByte((Byte)BinaryHeaderEnum.CrossAppDomainAssembly);
            sout.WriteInt32(assemId);
            sout.WriteInt32(assemblyIndex);
        }

        [System.Security.SecurityCritical] // implements Critical method
        public void Read(__BinaryParser input)
        {
            assemId = input.ReadInt32();
            assemblyIndex = input.ReadInt32();
        }

        public void Dump()
        {
            DumpInternal();
        }

        [Conditional("_LOGGING")]
        private void DumpInternal()
        {
            //if (BCLDebug.CheckEnabled("BINARY"))
            {
                BCLDebug.Trace("BINARY","*****BinaryCrossAppDomainAssembly*****");
                BinaryUtil.NVTraceI("binaryHeaderEnum (Byte)", "CrossAppDomainAssembly");
                BinaryUtil.NVTraceI("assemId (Int32)", assemId);        
                BinaryUtil.NVTraceI("assemblyIndex (Int32)", assemblyIndex);
                BCLDebug.Trace("BINARY","****************************");
            }
        }
    }

    [Serializable]
    public sealed class BinaryObject : IStreamable
    {
        public Int32 objectId;
        public Int32 mapId;

        public BinaryObject()
        {
        }

        public  void Set(Int32 objectId, Int32 mapId)
        {
            SerTrace.Log( this, "BinaryObject Set ",objectId," ",mapId);        
            this.objectId = objectId;
            this.mapId = mapId;
        }


        public  void Write(__BinaryWriter sout)
        {
            sout.WriteByte((Byte)BinaryHeaderEnum.Object);
            sout.WriteInt32(objectId);
            sout.WriteInt32(mapId);
        }

        [System.Security.SecurityCritical] // implements Critical method
        public void Read(__BinaryParser input)
        {
            objectId = input.ReadInt32();
            mapId = input.ReadInt32();
        }

        public  void Dump()
        {
            DumpInternal();
        }

        [Conditional("_LOGGING")]
        private void DumpInternal()
        {
            //if (BCLDebug.CheckEnabled("BINARY"))
            {
                BCLDebug.Trace("BINARY","*****BinaryObject*****");
                BinaryUtil.NVTraceI("binaryHeaderEnum (Byte)", "Object");
                BinaryUtil.NVTraceI("objectId (Int32)", objectId);      
                BinaryUtil.NVTraceI("mapId (Int32)", mapId);
                BCLDebug.Trace("BINARY","****************************");
            }
        }
    }

    [Serializable]
    public sealed class BinaryMethodCall
    {
        public String uri;
        public String methodName;
        public String typeName;
        public Type[] instArgs;
        public Object[] args;
        public Object methodSignature;
        public Object callContext;
        public String scallContext;
        public Object properties;
        public Type[] argTypes;
        public bool bArgsPrimitive = true;
        public MessageEnum messageEnum;
        public Object[] callA;

        // If the argument list contains only primitive or strings it is written out as part of the header
        // if not the args are written out as a separate array
        public Object[] WriteArray(String uri, String methodName, String typeName, Type[] instArgs, Object[] args, Object methodSignature, Object callContext, Object[] properties)
        {
            this.uri = uri;
            this.methodName = methodName;
            this.typeName = typeName;
            this.instArgs = instArgs;
            this.args = args;
            this.methodSignature = methodSignature;
            this.callContext = callContext;
            this.properties = properties;

            int arraySize = 0;
            if (args == null || args.Length == 0)
                messageEnum = MessageEnum.NoArgs;
            else
            {
                argTypes = new Type[args.Length];
                // Check if args are all string or primitives
                bArgsPrimitive = true;
                for (int i =0; i<args.Length; i++)
                {
                    if (args[i] != null)
                    {
                        argTypes[i] = args[i].GetType();
                        bool isArgPrimitive = Converter.ToCode(argTypes[i]) != InternalPrimitiveTypeE.Invalid;
                        if (!(isArgPrimitive || Object.ReferenceEquals(argTypes[i], Converter.typeofString)) || args[i] is ISerializable)
                        {
                            bArgsPrimitive = false;
                            break;
                        }
                    }
                }


                if (bArgsPrimitive)
                    messageEnum = MessageEnum.ArgsInline;
                else
                {
                    arraySize++;
                    messageEnum = MessageEnum.ArgsInArray;
                }
            }


            if (instArgs != null)
            {
                arraySize++;
                messageEnum |= MessageEnum.GenericMethod;
            }

            if (methodSignature != null)
            {
                arraySize++;
                messageEnum |= MessageEnum.MethodSignatureInArray;
            }

            if (callContext == null)
                messageEnum |= MessageEnum.NoContext;
            else if (callContext is String)
                messageEnum |= MessageEnum.ContextInline;
            else
            {
                arraySize++;
                messageEnum |= MessageEnum.ContextInArray;
            }

            if (properties != null)
            {
                arraySize++;
                messageEnum |= MessageEnum.PropertyInArray;
            }

            if (IOUtil.FlagTest(messageEnum, MessageEnum.ArgsInArray) && arraySize == 1)
            {
                messageEnum ^= MessageEnum.ArgsInArray;
                messageEnum |= MessageEnum.ArgsIsArray;
                return args;
            }


            if (arraySize > 0)
            {
                int arrayPosition = 0;
                callA = new Object[arraySize];
                if (IOUtil.FlagTest(messageEnum, MessageEnum.ArgsInArray))
                    callA[arrayPosition++] = args;

                if (IOUtil.FlagTest(messageEnum, MessageEnum.GenericMethod))
                    callA[arrayPosition++] = instArgs;
                
                if (IOUtil.FlagTest(messageEnum, MessageEnum.MethodSignatureInArray))
                    callA[arrayPosition++] = methodSignature;

                if (IOUtil.FlagTest(messageEnum, MessageEnum.ContextInArray))
                    callA[arrayPosition++] = callContext;

                if (IOUtil.FlagTest(messageEnum, MessageEnum.PropertyInArray))
                    callA[arrayPosition] = properties;

                 return callA;
            }
            else
                return null;
        }

        public void Write(__BinaryWriter sout)
        {
            sout.WriteByte((Byte)BinaryHeaderEnum.MethodCall);
            sout.WriteInt32((Int32)messageEnum);
            //IOUtil.WriteStringWithCode(uri, sout);
            IOUtil.WriteStringWithCode(methodName, sout);
            IOUtil.WriteStringWithCode(typeName, sout);
            if (IOUtil.FlagTest(messageEnum, MessageEnum.ContextInline))
                IOUtil.WriteStringWithCode((String)callContext, sout);

            if (IOUtil.FlagTest(messageEnum, MessageEnum.ArgsInline))
            {
                sout.WriteInt32(args.Length);
                for (int i=0; i<args.Length; i++)
                {
                    IOUtil.WriteWithCode(argTypes[i], args[i], sout);
                }

            }
        }

        [System.Security.SecurityCritical]  // auto-generated
        public void Read(__BinaryParser input)
        {
             messageEnum = (MessageEnum)input.ReadInt32();
             //uri = (String)IOUtil.ReadWithCode(input);
             methodName = (String)IOUtil.ReadWithCode(input);
             typeName = (String)IOUtil.ReadWithCode(input);

#if FEATURE_REMOTING
             if (IOUtil.FlagTest(messageEnum, MessageEnum.ContextInline))
             {
                 scallContext = (String)IOUtil.ReadWithCode(input);
                 LogicalCallContext lcallContext = new LogicalCallContext();
                 lcallContext.RemotingData.LogicalCallID = scallContext;
                 callContext = lcallContext;
             }
#endif             

             if (IOUtil.FlagTest(messageEnum, MessageEnum.ArgsInline))
                 args = IOUtil.ReadArgs(input);
        }
#if FEATURE_REMOTING
        [System.Security.SecurityCritical]  // auto-generated
        public IMethodCallMessage ReadArray(Object[] callA, Object handlerObject)
        {
            /*
            if (callA.Length != 7)
                throw new SerializationException(String.Format(ModifiedVulnerableBinaryFormatters.binary.Environment.GetResourceString("Serialization_Method")));
                */

            if (IOUtil.FlagTest(messageEnum, MessageEnum.ArgsIsArray))
            {
                args = callA;
            }
            else
            {
                int arrayPosition = 0;
                
                if (IOUtil.FlagTest(messageEnum, MessageEnum.ArgsInArray))
                {
                    if (callA.Length < arrayPosition)
                        throw new SerializationException(Environment.GetResourceString("Serialization_Method"));
                    args = (Object[])callA[arrayPosition++];
                }

                if (IOUtil.FlagTest(messageEnum, MessageEnum.GenericMethod))
                {
                    if (callA.Length < arrayPosition)
                        throw new SerializationException(Environment.GetResourceString("Serialization_Method"));
                    instArgs = (Type[])callA[arrayPosition++];
                }

                if (IOUtil.FlagTest(messageEnum, MessageEnum.MethodSignatureInArray))
                {
                    if (callA.Length < arrayPosition)
                        throw new SerializationException(Environment.GetResourceString("Serialization_Method"));
                    methodSignature = callA[arrayPosition++];
                }

                if (IOUtil.FlagTest(messageEnum, MessageEnum.ContextInArray))
                {
                    if (callA.Length < arrayPosition)
                        throw new SerializationException(Environment.GetResourceString("Serialization_Method"));
                    callContext = callA[arrayPosition++];
                }

                if (IOUtil.FlagTest(messageEnum, MessageEnum.PropertyInArray))
                {
                    if (callA.Length < arrayPosition)
                        throw new SerializationException(Environment.GetResourceString("Serialization_Method"));
                    properties = callA[arrayPosition++];
                }
            }

            return new MethodCall(handlerObject, new BinaryMethodCallMessage(uri, methodName, typeName, instArgs, args, methodSignature, (LogicalCallContext)callContext, (Object[])properties));
        }
#endif // FEATURE_REMOTING
        public void Dump()
        {
            DumpInternal();
        }

        [Conditional("_LOGGING")]
        private void DumpInternal()
        {
            //if (BCLDebug.CheckEnabled("BINARY"))
            {
                BCLDebug.Trace("BINARY","*****BinaryMethodCall*****");
                BinaryUtil.NVTraceI("binaryHeaderEnum (Byte)", "MethodCall");
                BinaryUtil.NVTraceI("messageEnum (Int32)", ((Enum)messageEnum).ToString());
                //BinaryUtil.NVTraceI("uri",uri);
                BinaryUtil.NVTraceI("methodName",methodName);
                BinaryUtil.NVTraceI("typeName",typeName);
                if (IOUtil.FlagTest(messageEnum, MessageEnum.ContextInline))
                {
                    if (callContext is String)
                        BinaryUtil.NVTraceI("callContext", (String)callContext);   
                    else
                        BinaryUtil.NVTraceI("callContext", scallContext);   
                }

                if (IOUtil.FlagTest(messageEnum, MessageEnum.ArgsInline))
                {
                    BinaryUtil.NVTraceI("args Length", args.Length);
                    for (int i=0; i<args.Length; i++)
                    {
                        BinaryUtil.NVTraceI("arg["+i+"]", args[i]);
                    }
                }

                BCLDebug.Trace("BINARY","****************************");
            }
        }
    }

    [Serializable]
    public sealed class BinaryMethodReturn : IStreamable
    {
        public Object returnValue;
        public Object[] args;
        public Exception exception;
        public Object callContext;
        public String scallContext;
        public Object properties;
        public Type[] argTypes;
        public bool bArgsPrimitive = true;
        public MessageEnum messageEnum;
        public Object[] callA;
        public Type returnType;
        public static Object instanceOfVoid = FormatterServices.GetUninitializedObject(Converter.typeofSystemVoid);

        [System.Security.SecuritySafeCritical] // static constructors should be safe to call
        static BinaryMethodReturn()
        {
        }

        public BinaryMethodReturn()
        {
        }

        // If the argument list contains only primitive or strings it is written out as part of the header
        // if not the args are written out as a separate array
        public Object[] WriteArray(Object returnValue, Object[] args, Exception exception, Object callContext, Object[] properties)
        {
            SerTrace.Log(this, "WriteArray returnValue ",returnValue, "exception ", exception, " callContext ",callContext," properties ", properties);

            this.returnValue = returnValue;
            this.args = args;
            this.exception = exception;
            this.callContext = callContext;
            this.properties = properties;

            int arraySize = 0;
            if (args == null || args.Length == 0)
                messageEnum = MessageEnum.NoArgs;
            else
            {
                argTypes = new Type[args.Length];

                // Check if args are all string or primitives

                bArgsPrimitive = true;
                for (int i =0; i<args.Length; i++)
                {
                    if (args[i] != null)
                    {
                        argTypes[i] = args[i].GetType();
                        bool isArgPrimitive = Converter.ToCode(argTypes[i]) != InternalPrimitiveTypeE.Invalid;
                        if (!(isArgPrimitive || Object.ReferenceEquals(argTypes[i], Converter.typeofString)))
                        {
                            bArgsPrimitive = false;
                            break;
                        }
                    }
                }

                if (bArgsPrimitive)
                    messageEnum = MessageEnum.ArgsInline;
                else
                {
                    arraySize++;
                    messageEnum = MessageEnum.ArgsInArray;
                }
            }


            if (returnValue == null)
                messageEnum |= MessageEnum.NoReturnValue;
            else if (returnValue.GetType() == typeof(void))
                messageEnum |= MessageEnum.ReturnValueVoid;
            else
            {
                returnType = returnValue.GetType();
                bool isReturnTypePrimitive = Converter.ToCode(returnType) != InternalPrimitiveTypeE.Invalid;
                if (isReturnTypePrimitive || Object.ReferenceEquals(returnType, Converter.typeofString))
                    messageEnum |= MessageEnum.ReturnValueInline;
                else
                {
                    arraySize++;
                    messageEnum |= MessageEnum.ReturnValueInArray;
                }
            }

            if (exception != null)
            {
                arraySize++;
                messageEnum |= MessageEnum.ExceptionInArray;
            }

            if (callContext == null)
                messageEnum |= MessageEnum.NoContext;
            else if (callContext is String)
                messageEnum |= MessageEnum.ContextInline;
            else
            {
                arraySize++;
                messageEnum |= MessageEnum.ContextInArray;
            }

            if (properties != null)
            {
                arraySize++;
                messageEnum |= MessageEnum.PropertyInArray;
            }

            if (IOUtil.FlagTest(messageEnum, MessageEnum.ArgsInArray) && (arraySize == 1))
            {
                messageEnum ^= MessageEnum.ArgsInArray;
                messageEnum |= MessageEnum.ArgsIsArray;
                return args;
            }

            if (arraySize > 0)
            {
                int arrayPosition = 0;
                callA = new Object[arraySize];
                if (IOUtil.FlagTest(messageEnum, MessageEnum.ArgsInArray))
                    callA[arrayPosition++] = args;

                if (IOUtil.FlagTest(messageEnum, MessageEnum.ReturnValueInArray))
                    callA[arrayPosition++] = returnValue;

                if (IOUtil.FlagTest(messageEnum, MessageEnum.ExceptionInArray))
                    callA[arrayPosition++] = exception;

                if (IOUtil.FlagTest(messageEnum, MessageEnum.ContextInArray))
                    callA[arrayPosition++] = callContext;

                if (IOUtil.FlagTest(messageEnum, MessageEnum.PropertyInArray))
                    callA[arrayPosition] = properties;

                 return callA;
            }
            else
                return null;
        }


        public void Write(__BinaryWriter sout) 
        {
            sout.WriteByte((Byte)BinaryHeaderEnum.MethodReturn);
            sout.WriteInt32((Int32)messageEnum);

            if (IOUtil.FlagTest(messageEnum, MessageEnum.ReturnValueInline))
            {
                IOUtil.WriteWithCode(returnType, returnValue, sout);
            }

            if (IOUtil.FlagTest(messageEnum, MessageEnum.ContextInline))
                IOUtil.WriteStringWithCode((String)callContext, sout);

            if (IOUtil.FlagTest(messageEnum, MessageEnum.ArgsInline))
            {
                sout.WriteInt32(args.Length);
                for (int i=0; i<args.Length; i++)
                {
                    IOUtil.WriteWithCode(argTypes[i], args[i], sout);
                }
            }
        }

        [System.Security.SecurityCritical]  // auto-generated
        public void Read(__BinaryParser input)
        {
             messageEnum = (MessageEnum)input.ReadInt32();

             if (IOUtil.FlagTest(messageEnum, MessageEnum.NoReturnValue))
                 returnValue = null;
             else if (IOUtil.FlagTest(messageEnum, MessageEnum.ReturnValueVoid))
             {
                 returnValue = instanceOfVoid;            
             }
             else if (IOUtil.FlagTest(messageEnum, MessageEnum.ReturnValueInline))
                 returnValue = IOUtil.ReadWithCode(input);

#if FEATURE_REMOTING
             if (IOUtil.FlagTest(messageEnum, MessageEnum.ContextInline))
             {
                 scallContext = (String)IOUtil.ReadWithCode(input);
                 LogicalCallContext lcallContext = new LogicalCallContext();
                 lcallContext.RemotingData.LogicalCallID = scallContext;
                 callContext = lcallContext;
             }
#endif
             if (IOUtil.FlagTest(messageEnum, MessageEnum.ArgsInline))
                 args = IOUtil.ReadArgs(input);
        }

#if FEATURE_REMOTING
        [System.Security.SecurityCritical]  // auto-generated
        public IMethodReturnMessage ReadArray(Object[] returnA, IMethodCallMessage methodCallMessage, Object handlerObject)
        {
            if (IOUtil.FlagTest(messageEnum, MessageEnum.ArgsIsArray))
            {
                args = returnA;
            }
            else
            {
                int arrayPosition = 0;
                    
                if (IOUtil.FlagTest(messageEnum, MessageEnum.ArgsInArray))
                {
                    if (returnA.Length < arrayPosition)
                        throw new SerializationException(Environment.GetResourceString("Serialization_Method"));
                    args = (Object[])returnA[arrayPosition++];
                }

                if (IOUtil.FlagTest(messageEnum, MessageEnum.ReturnValueInArray))
                {
                    if (returnA.Length < arrayPosition)
                        throw new SerializationException(Environment.GetResourceString("Serialization_Method"));
                    returnValue = returnA[arrayPosition++];
                }

                if (IOUtil.FlagTest(messageEnum, MessageEnum.ExceptionInArray))
                {
                    if (returnA.Length < arrayPosition)
                        throw new SerializationException(Environment.GetResourceString("Serialization_Method"));
                    exception = (Exception)returnA[arrayPosition++];
                }

                if (IOUtil.FlagTest(messageEnum, MessageEnum.ContextInArray))
                {
                   if (returnA.Length < arrayPosition)
                        throw new SerializationException(Environment.GetResourceString("Serialization_Method"));
                    callContext = returnA[arrayPosition++];
                }

                if (IOUtil.FlagTest(messageEnum, MessageEnum.PropertyInArray))
                {
                    if (returnA.Length < arrayPosition)
                        throw new SerializationException(Environment.GetResourceString("Serialization_Method"));
                    properties = returnA[arrayPosition++];
                }
            }
            return new MethodResponse(methodCallMessage, handlerObject,  new BinaryMethodReturnMessage(returnValue, args, exception, (LogicalCallContext)callContext, (Object[])properties));
        }
#endif // FEATURE_REMOTING
        public void Dump()
        {
            DumpInternal();
        }

        [Conditional("_LOGGING")]
        private void DumpInternal()
        {
            //if (BCLDebug.CheckEnabled("BINARY"))
            {
                BCLDebug.Trace("BINARY","*****BinaryMethodReturn*****");
                BinaryUtil.NVTraceI("binaryHeaderEnum (Byte)", "MethodReturn");
                BinaryUtil.NVTraceI("messageEnum (Int32)", ((Enum)messageEnum).ToString());

                if (IOUtil.FlagTest(messageEnum, MessageEnum.ReturnValueInline))
                    BinaryUtil.NVTraceI("returnValue", returnValue);

                if (IOUtil.FlagTest(messageEnum, MessageEnum.ContextInline))
                {
                    if (callContext is String)
                        BinaryUtil.NVTraceI("callContext", (String)callContext);   
                    else
                        BinaryUtil.NVTraceI("callContext", scallContext);   
                }

                if (IOUtil.FlagTest(messageEnum, MessageEnum.ArgsInline))
                {
                    BinaryUtil.NVTraceI("args Length", args.Length);
                    for (int i=0; i<args.Length; i++)
                    {
                        BinaryUtil.NVTraceI("arg["+i+"]", args[i]);
                    }
                }

                BCLDebug.Trace("BINARY","****************************");
            }
        }
    }

    [Serializable]
    public sealed class BinaryObjectString : IStreamable
    {
        public Int32 objectId;
        public String value;

        public BinaryObjectString()
        {
        }

        public  void Set(Int32 objectId, String value)
        {
            SerTrace.Log(this, "BinaryObjectString set ",objectId," ",value);
            this.objectId = objectId;
            this.value = value;
        }   


        public  void Write(__BinaryWriter sout)
        {
            sout.WriteByte((Byte)BinaryHeaderEnum.ObjectString);
            sout.WriteInt32(objectId);
            sout.WriteString(value);
        }

        [System.Security.SecurityCritical] // implements Critical method
        public void Read(__BinaryParser input)
        {
            objectId = input.ReadInt32();
            value = input.ReadString();
        }

        public  void Dump()
        {
            DumpInternal();
        }

        [Conditional("_LOGGING")]
        private void DumpInternal()
        {
            //if (BCLDebug.CheckEnabled("BINARY"))
            {
                BCLDebug.Trace("BINARY","*****BinaryObjectString*****");
                BinaryUtil.NVTraceI("binaryHeaderEnum (Byte)", "ObjectString");
                BinaryUtil.NVTraceI("objectId (Int32)", objectId);              
                BinaryUtil.NVTraceI("value (UTF)", value);
                BCLDebug.Trace("BINARY","****************************");
            }
        }
    }

    [Serializable]
    public sealed class BinaryCrossAppDomainString : IStreamable
    {
        public Int32 objectId;
        public Int32 value;

        public BinaryCrossAppDomainString()
        {
        }

        public  void Write(__BinaryWriter sout)
        {
            sout.WriteByte((Byte)BinaryHeaderEnum.CrossAppDomainString);
            sout.WriteInt32(objectId);
            sout.WriteInt32(value);
        }

        [System.Security.SecurityCritical] // implements Critical method
        public void Read(__BinaryParser input)
        {
            objectId = input.ReadInt32();
            value = input.ReadInt32();
        }

        public  void Dump()
        {
            DumpInternal();
        }

        [Conditional("_LOGGING")]
        private void DumpInternal()
        {
            //if (BCLDebug.CheckEnabled("BINARY"))
            {
                BCLDebug.Trace("BINARY","*****BinaryCrossAppDomainString*****");
                BinaryUtil.NVTraceI("binaryHeaderEnum (Byte)", "CrossAppDomainString");
                BinaryUtil.NVTraceI("objectId (Int32)", objectId);              
                BinaryUtil.NVTraceI("value (Int32)", value);
                BCLDebug.Trace("BINARY","****************************");
            }
        }
    }

    [Serializable]
    public sealed class BinaryCrossAppDomainMap : IStreamable
    {
        public Int32 crossAppDomainArrayIndex;

        public BinaryCrossAppDomainMap()
        {
        }

        public  void Write(__BinaryWriter sout)
        {
            sout.WriteByte((Byte)BinaryHeaderEnum.CrossAppDomainMap);
            sout.WriteInt32(crossAppDomainArrayIndex);
        }

        [System.Security.SecurityCritical] // implements Critical method
        public void Read(__BinaryParser input)
        {
            crossAppDomainArrayIndex = input.ReadInt32();
        }

        public  void Dump()
        {
            DumpInternal();
        }

        [Conditional("_LOGGING")]
        private void DumpInternal()
        {
            //if (BCLDebug.CheckEnabled("BINARY"))
            {
                BCLDebug.Trace("BINARY","*****BinaryCrossAppDomainMap*****");
                BinaryUtil.NVTraceI("binaryHeaderEnum (Byte)", "CrossAppDomainMap");
                BinaryUtil.NVTraceI("crossAppDomainArrayIndex (Int32)", crossAppDomainArrayIndex);              
                BCLDebug.Trace("BINARY","****************************");
            }
        }
    }

    [Serializable]
    public sealed class MemberPrimitiveTyped : IStreamable
    {
        public InternalPrimitiveTypeE primitiveTypeEnum;
        public Object value;

        public MemberPrimitiveTyped()
        {
        }

        public void Set(InternalPrimitiveTypeE primitiveTypeEnum, Object value)
        {
            SerTrace.Log(this, "MemberPrimitiveTyped Set ",((Enum)primitiveTypeEnum).ToString()," ",value);
            this.primitiveTypeEnum = primitiveTypeEnum;
            this.value = value;
        }   


        public  void Write(__BinaryWriter sout)
        {
            sout.WriteByte((Byte)BinaryHeaderEnum.MemberPrimitiveTyped);
            sout.WriteByte((Byte)primitiveTypeEnum); //pdj
            sout.WriteValue(primitiveTypeEnum, value);
        }

        [System.Security.SecurityCritical] // implements Critical method
        public void Read(__BinaryParser input)
        {
            primitiveTypeEnum = (InternalPrimitiveTypeE)input.ReadByte(); //PDJ
            value = input.ReadValue(primitiveTypeEnum);     
        }

        public  void Dump()
        {
            DumpInternal();
        }

        [Conditional("_LOGGING")]
        private void DumpInternal()
        {
            //if (BCLDebug.CheckEnabled("BINARY"))
            {
                BCLDebug.Trace("BINARY","*****MemberPrimitiveTyped*****");
                BinaryUtil.NVTraceI("binaryHeaderEnum (Byte)", "MemberPrimitiveTyped");
                BinaryUtil.NVTraceI("primitiveTypeEnum (Byte)", ((Enum)primitiveTypeEnum).ToString());
                BinaryUtil.NVTraceI("value ("+ Converter.ToComType(primitiveTypeEnum)+")", value);
                BCLDebug.Trace("BINARY","****************************");
            }
        }
    }

    [Serializable]
    public sealed class BinaryObjectWithMap : IStreamable
    {
        public BinaryHeaderEnum binaryHeaderEnum;
        public Int32 objectId;
        public String name;
        public Int32 numMembers;
        public String[] memberNames;
        public Int32 assemId;   

        public BinaryObjectWithMap()
        {
        }

        public BinaryObjectWithMap(BinaryHeaderEnum binaryHeaderEnum)
        {
            this.binaryHeaderEnum = binaryHeaderEnum;
        }

        public  void Set(Int32 objectId, String name, Int32 numMembers, String[] memberNames, Int32 assemId)
        {
#if _DEBUG            
            SerTrace.Log(this, "BinaryObjectWithMap Set ",objectId," assemId ",assemId," ",Util.PString(name)," numMembers ",numMembers);
#endif
            this.objectId = objectId;
            this.name = name;
            this.numMembers = numMembers;
            this.memberNames = memberNames;
            this.assemId = assemId;

            if (assemId > 0)
                binaryHeaderEnum = BinaryHeaderEnum.ObjectWithMapAssemId;
            else
                binaryHeaderEnum = BinaryHeaderEnum.ObjectWithMap;

        }

        public  void Write(__BinaryWriter sout)
        {

            sout.WriteByte((Byte)binaryHeaderEnum);
            sout.WriteInt32(objectId);
            sout.WriteString(name);
            sout.WriteInt32(numMembers);
            for (int i=0; i<numMembers; i++)
                sout.WriteString(memberNames[i]);
            if (assemId > 0)
                sout.WriteInt32(assemId);
        }

        [System.Security.SecurityCritical] // implements Critical method
        public void Read(__BinaryParser input)
        {
            objectId = input.ReadInt32();
            name = input.ReadString();
            numMembers = input.ReadInt32();
            memberNames = new String[numMembers];
            for (int i=0; i<numMembers; i++)
            {
                memberNames[i] = input.ReadString();
                SerTrace.Log(this, "BinaryObjectWithMap Read ",i," ",memberNames[i]);
            }

            if (binaryHeaderEnum == BinaryHeaderEnum.ObjectWithMapAssemId)
            {
                assemId = input.ReadInt32();
            }
        }


        public  void Dump()
        {
            DumpInternal();
        }

        [Conditional("_LOGGING")]
        private void DumpInternal()
        {
            //if (BCLDebug.CheckEnabled("BINARY"))
            {
                BCLDebug.Trace("BINARY","*****BinaryObjectWithMap*****");
                BinaryUtil.NVTraceI("binaryHeaderEnum (Byte)", ((Enum)binaryHeaderEnum).ToString());
                BinaryUtil.NVTraceI("objectId (Int32)", objectId);
                BinaryUtil.NVTraceI("name (UTF)", name);
                BinaryUtil.NVTraceI("numMembers (Int32)", numMembers);
                for (int i=0; i<numMembers; i++)
                    BinaryUtil.NVTraceI("memberNames (UTF)", memberNames[i]);
                if (binaryHeaderEnum == BinaryHeaderEnum.ObjectWithMapAssemId)
                BinaryUtil.NVTraceI("assemId (Int32)", assemId);
                BCLDebug.Trace("BINARY","****************************");
            }
        }
    }

    [Serializable]
    public  sealed class BinaryObjectWithMapTyped : IStreamable
    {
        public BinaryHeaderEnum binaryHeaderEnum;     
        public Int32 objectId;
        public String name;
        public Int32 numMembers;
        public String[] memberNames;
        public BinaryTypeEnum[] binaryTypeEnumA;
        public Object[] typeInformationA;
        public Object[] typeInformationB; // This is a hack so we can cross over from deserialized to serialized but not needed really - so we can replace all the strings with empty ('') to make the payload shorter
        public Int32[] memberAssemIds;
        public Int32 assemId;

        public BinaryObjectWithMapTyped()
        {
        }

        public BinaryObjectWithMapTyped(BinaryHeaderEnum binaryHeaderEnum)
        {
            this.binaryHeaderEnum = binaryHeaderEnum;
        }

#if false
        public BinaryObjectWithMapTyped Copy()
        {
        BinaryObjectWithMapTyped newBOWM = new BinaryObjectWithMapTyped(binaryHeaderEnum);

        String[] newMemberNames = new String[numMembers];
        Array.Copy(memberNames, newMemberNames, numMembers);
        BinaryTypeEnum[] newBinaryTypeEnumA = new BinaryTypeEnum[binaryTypeEnumA.Length];
        Array.Copy(binaryTypeEnumA, newBinaryTypeEnumA, binaryTypeEnumA.Length);
        Object[] newTypeInformationA = new Object[typeInformationA.Length];
        Array.Copy(typeInformationA, newTypeInformationA, typeInformationA.Length);
        Int32[] newMemberAssemIds = new Int32[memberAssemIds.Length];
        Array.Copy(memberAssemIds, newMemberAssemIds, memberAssemIds.Length);

        newBOWM.Set(objectId, name, numMembers, newMemberNames, newBinaryTypeEnumA, newTypeInformationA, newMemberAssemIds, assemId);
        return newBOWM;
        }
#endif


        public  void Set(Int32 objectId, String name, Int32 numMembers, String[] memberNames, BinaryTypeEnum[] binaryTypeEnumA, Object[] typeInformationA, Int32[] memberAssemIds, Int32 assemId)
        {
            SerTrace.Log(this, "BinaryObjectWithMapTyped Set ",objectId," assemId ",assemId," ",name," numMembers ",numMembers);
            this.objectId = objectId;
            this.assemId = assemId;         
            this.name = name;
            this.numMembers = numMembers;
            this.memberNames = memberNames;
            this.binaryTypeEnumA = binaryTypeEnumA;
            this.typeInformationA = typeInformationA;
            this.memberAssemIds = memberAssemIds;
            this.assemId = assemId;

            if (assemId > 0)
                binaryHeaderEnum = BinaryHeaderEnum.ObjectWithMapTypedAssemId;
            else
                binaryHeaderEnum = BinaryHeaderEnum.ObjectWithMapTyped;             
        }

        public void Int64ToInt32inObjectEnumArray(object[] objEnumArray)
        {
            if (objEnumArray != null)
            {
                for (int i = 0; i < objEnumArray.Length; i++)
                {
                    if (objEnumArray[i] != null)
                    {
                        if (objEnumArray[i].GetType().Name == "Int64")
                        {
                            objEnumArray[i] = Convert.ToInt32(objEnumArray[i]);
                        }
                    }
                }
            }
        }

        public void Write(__BinaryWriter sout)
        {
            Int64ToInt32inObjectEnumArray(typeInformationA);
            Int64ToInt32inObjectEnumArray(typeInformationB);

            sout.WriteByte((Byte)binaryHeaderEnum);
            sout.WriteInt32(objectId);
            sout.WriteString(name);
            sout.WriteInt32(numMembers);
            for (int i = 0; i < numMembers; i++)
                sout.WriteString(memberNames[i]);
            for (int i = 0; i < numMembers; i++)
                sout.WriteByte((Byte)binaryTypeEnumA[i]);
            for (int i = 0; i < numMembers; i++)
            {
                //if (binaryTypeEnumA[i] != BinaryTypeEnum.ObjectUrt && binaryTypeEnumA[i] != BinaryTypeEnum.ObjectUser)
                if (typeInformationB != null)
                    BinaryConverter.WriteTypeInfo(binaryTypeEnumA[i], typeInformationB[i], memberAssemIds[i], sout);
                else
                    BinaryConverter.WriteTypeInfo(binaryTypeEnumA[i], typeInformationA[i], memberAssemIds[i], sout);
            }

            if (assemId > 0)
            {
                sout.WriteInt32(assemId);
            }

        }

        [System.Security.SecurityCritical] // implements Critical method
        public void Read(__BinaryParser input)
        {
            // binaryHeaderEnum has already been read
            objectId = input.ReadInt32();
            name = input.ReadString();
            numMembers = input.ReadInt32();
            memberNames = new String[numMembers];
            binaryTypeEnumA = new BinaryTypeEnum[numMembers];
            typeInformationA = new Object[numMembers];
            typeInformationB = new Object[numMembers];
            memberAssemIds = new Int32[numMembers];
            for (int i=0; i<numMembers; i++)
                memberNames[i] = input.ReadString();
            for (int i=0; i<numMembers; i++)
                binaryTypeEnumA[i] = (BinaryTypeEnum)input.ReadByte();
            for (int i = 0; i < numMembers; i++)
            {
                typeInformationB[i] = BinaryConverter.ReadTypeInfo(binaryTypeEnumA[i], input, out memberAssemIds[i]);
                if (binaryTypeEnumA[i] != BinaryTypeEnum.ObjectUrt && binaryTypeEnumA[i] != BinaryTypeEnum.ObjectUser)
                    typeInformationA[i] = typeInformationB[i];
            }

            if (binaryHeaderEnum == BinaryHeaderEnum.ObjectWithMapTypedAssemId)
            {
                assemId = input.ReadInt32();
            }
        }

#if _DEBUG
        public  void Dump()
        {
            DumpInternal();
        }

        [Conditional("_LOGGING")]
        private void DumpInternal()
        {
            //if (BCLDebug.CheckEnabled("BINARY"))
            {
                BCLDebug.Trace("BINARY","*****BinaryObjectWithMapTyped*****");
                BinaryUtil.NVTraceI("binaryHeaderEnum (Byte)", ((Enum)binaryHeaderEnum).ToString());
                BinaryUtil.NVTraceI("objectId (Int32)", objectId);          
                BinaryUtil.NVTraceI("name (UTF)", name);
                BinaryUtil.NVTraceI("numMembers (Int32)", numMembers);
                for (int i=0; i<numMembers; i++)
                    BinaryUtil.NVTraceI("memberNames (UTF)", memberNames[i]);
                for (int i=0; i<numMembers; i++)
                    BinaryUtil.NVTraceI("binaryTypeEnum("+i+") (Byte)", ((Enum)binaryTypeEnumA[i]).ToString());
                for (int i=0; i<numMembers; i++)
                    if ((binaryTypeEnumA[i] == BinaryTypeEnum.Primitive) || 
                        (binaryTypeEnumA[i] == BinaryTypeEnum.PrimitiveArray) || 
                        (binaryTypeEnumA[i] == BinaryTypeEnum.ObjectUrt) || 
                        (binaryTypeEnumA[i] == BinaryTypeEnum.ObjectUser))
                    {
                        BinaryUtil.NVTraceI("typeInformation("+i+") "+BinaryConverter.TypeInfoTraceString(typeInformationA[i]), typeInformationA[i]);
                        if (binaryTypeEnumA[i] == BinaryTypeEnum.ObjectUser)
                             BinaryUtil.NVTraceI("memberAssemId("+i+") (Int32)", memberAssemIds[i]);
                    }

                    /*
                    for (int i=0; i<numMembers; i++)
                    {
                    if (binaryTypeEnumA[i] == BinaryTypeEnum.ObjectUser)
                    BinaryUtil.NVTraceI("memberAssemId("+i+") (Int32)", memberAssemIds[i]);
                    }
            */
                if (binaryHeaderEnum == BinaryHeaderEnum.ObjectWithMapTypedAssemId)
                    BinaryUtil.NVTraceI("assemId (Int32)", assemId);
                BCLDebug.Trace("BINARY","****************************");
            }
        }
#endif
    }

    [Serializable]
    public  sealed class BinaryArray : IStreamable
    {
        public Int32 objectId;
        public Int32 rank;
        public Int32[] lengthA;
        public Int32[] lowerBoundA;
        public BinaryTypeEnum binaryTypeEnum;
        public Object typeInformation;
        public int assemId = 0;

        public BinaryHeaderEnum binaryHeaderEnum;
        public BinaryArrayTypeEnum binaryArrayTypeEnum;

        public BinaryArray()
        {
            SerTrace.Log( this, "BinaryArray Constructor 1 ");
        }

        // Read constructor 
        public BinaryArray(BinaryHeaderEnum binaryHeaderEnum)
        {
            SerTrace.Log( this, "BinaryArray Constructor 2 ",   ((Enum)binaryHeaderEnum).ToString());
            this.binaryHeaderEnum = binaryHeaderEnum;
        }


        public void Set(Int32 objectId, Int32 rank, Int32[] lengthA, Int32[] lowerBoundA, BinaryTypeEnum binaryTypeEnum, Object typeInformation, BinaryArrayTypeEnum binaryArrayTypeEnum, int assemId)
        {
            SerTrace.Log( this, "BinaryArray Set objectId ",objectId," rank ",rank," ",((Enum)binaryTypeEnum).ToString(),", assemId ",assemId);
            this.objectId = objectId;
            this.binaryArrayTypeEnum = binaryArrayTypeEnum;
            this.rank = rank;
            this.lengthA = lengthA;
            this.lowerBoundA = lowerBoundA;
            this.binaryTypeEnum = binaryTypeEnum;
            this.typeInformation = typeInformation;
            this.assemId = assemId;
            binaryHeaderEnum = BinaryHeaderEnum.Array;

            if (binaryArrayTypeEnum == BinaryArrayTypeEnum.Single)
            {
                if (binaryTypeEnum == BinaryTypeEnum.Primitive)
                    binaryHeaderEnum = BinaryHeaderEnum.ArraySinglePrimitive;
                else if (binaryTypeEnum == BinaryTypeEnum.String)
                    binaryHeaderEnum = BinaryHeaderEnum.ArraySingleString;
                else if (binaryTypeEnum == BinaryTypeEnum.Object)
                    binaryHeaderEnum = BinaryHeaderEnum.ArraySingleObject;
            }
            SerTrace.Log( this, "BinaryArray Set Exit ",((Enum)binaryHeaderEnum).ToString());
        }


        public  void Write(__BinaryWriter sout)
        {
            SerTrace.Log( this, "Write");
            switch (binaryHeaderEnum)
            {
                case BinaryHeaderEnum.ArraySinglePrimitive:
                    sout.WriteByte((Byte)binaryHeaderEnum);
                    sout.WriteInt32(objectId);
                    sout.WriteInt32(lengthA[0]);
                    //sout.WriteByte((Byte)((InternalPrimitiveTypeE)typeInformation));
                    sout.WriteByte((Byte)((InternalPrimitiveTypeE)Convert.ToInt32(typeInformation)));
                    break;
                case BinaryHeaderEnum.ArraySingleString:
                    sout.WriteByte((Byte)binaryHeaderEnum);
                    sout.WriteInt32(objectId);
                    sout.WriteInt32(lengthA[0]);
                    break;
                case BinaryHeaderEnum.ArraySingleObject:
                    sout.WriteByte((Byte)binaryHeaderEnum);
                    sout.WriteInt32(objectId);
                    sout.WriteInt32(lengthA[0]);
                    break;
                default:
                    sout.WriteByte((Byte)binaryHeaderEnum);
                    sout.WriteInt32(objectId);
                    sout.WriteByte((Byte)binaryArrayTypeEnum);
                    sout.WriteInt32(rank);
                    for (int i=0; i<rank; i++)
                        sout.WriteInt32(lengthA[i]);
                    if ((binaryArrayTypeEnum == BinaryArrayTypeEnum.SingleOffset) ||
                        (binaryArrayTypeEnum == BinaryArrayTypeEnum.JaggedOffset) ||
                        (binaryArrayTypeEnum == BinaryArrayTypeEnum.RectangularOffset))
                    {
                        for (int i=0; i<rank; i++)
                            sout.WriteInt32(lowerBoundA[i]);
                    }
                    sout.WriteByte((Byte)binaryTypeEnum);
                    BinaryConverter.WriteTypeInfo(binaryTypeEnum, typeInformation, assemId, sout);
                    break;
            }

        }

        [System.Security.SecurityCritical] // implements Critical method
        public void Read(__BinaryParser input)
        {
            switch (binaryHeaderEnum)
            {
                case BinaryHeaderEnum.ArraySinglePrimitive:
                    objectId = input.ReadInt32();
                    lengthA = new int[1];
                    lengthA[0] = input.ReadInt32();
                    binaryArrayTypeEnum = BinaryArrayTypeEnum.Single;
                    rank = 1;
                    lowerBoundA = new Int32[rank];
                    binaryTypeEnum = BinaryTypeEnum.Primitive;
                    typeInformation = (InternalPrimitiveTypeE)input.ReadByte();
                    break;
                case BinaryHeaderEnum.ArraySingleString:
                    objectId = input.ReadInt32();
                    lengthA = new int[1];
                    lengthA[0] = (int)input.ReadInt32();
                    binaryArrayTypeEnum = BinaryArrayTypeEnum.Single;
                    rank = 1;
                    lowerBoundA = new Int32[rank];
                    binaryTypeEnum = BinaryTypeEnum.String;
                    typeInformation = null;
                    break;
                case BinaryHeaderEnum.ArraySingleObject:
                    objectId = input.ReadInt32();
                    lengthA = new int[1];
                    lengthA[0] = (int)input.ReadInt32();
                    binaryArrayTypeEnum = BinaryArrayTypeEnum.Single;
                    rank = 1;
                    lowerBoundA = new Int32[rank];
                    binaryTypeEnum = BinaryTypeEnum.Object;
                    typeInformation = null;
                    break;
        default:
                    objectId = input.ReadInt32();
                    binaryArrayTypeEnum = (BinaryArrayTypeEnum)input.ReadByte();
                    rank = input.ReadInt32();
                    lengthA = new Int32[rank];
                    lowerBoundA = new Int32[rank];
                    for (int i=0; i<rank; i++)
                        lengthA[i] = input.ReadInt32();         
                    if ((binaryArrayTypeEnum == BinaryArrayTypeEnum.SingleOffset) ||
                        (binaryArrayTypeEnum == BinaryArrayTypeEnum.JaggedOffset) ||
                        (binaryArrayTypeEnum == BinaryArrayTypeEnum.RectangularOffset))
                    {
                        for (int i=0; i<rank; i++)
                            lowerBoundA[i] = input.ReadInt32();
                    }
                    binaryTypeEnum = (BinaryTypeEnum)input.ReadByte();
                    typeInformation = BinaryConverter.ReadTypeInfo(binaryTypeEnum, input, out assemId);
                    break;
            }
        }

#if _DEBUG                        
        public  void Dump()
        {
            DumpInternal();
        }

        [Conditional("_LOGGING")]
        private void DumpInternal()
        {
            //if (BCLDebug.CheckEnabled("BINARY"))
            {
                switch (binaryHeaderEnum)
                {
                    case BinaryHeaderEnum.ArraySinglePrimitive:
                        BCLDebug.Trace("BINARY","*****ArraySinglePrimitive*****");
                        BinaryUtil.NVTraceI("binaryHeaderEnum (Byte)", ((Enum)binaryHeaderEnum).ToString());
                        BinaryUtil.NVTraceI("objectId (Int32)", objectId);                              
                        BinaryUtil.NVTraceI("length (Int32)", lengthA[0]);
                        BinaryUtil.NVTraceI("InternalPrimitiveTypeE (Byte)", ((Enum)typeInformation).ToString());
                        BCLDebug.Trace("BINARY","****************************");
                        break;
                    case BinaryHeaderEnum.ArraySingleString:
                        BCLDebug.Trace("BINARY","*****ArraySingleString*****");
                        BinaryUtil.NVTraceI("binaryHeaderEnum (Byte)", ((Enum)binaryHeaderEnum).ToString());
                        BinaryUtil.NVTraceI("objectId (Int32)", objectId);
                        BinaryUtil.NVTraceI("length (Int32)", lengthA[0]);
                        BCLDebug.Trace("BINARY","****************************");
                        break;
                    case BinaryHeaderEnum.ArraySingleObject:
                        BCLDebug.Trace("BINARY","*****ArraySingleObject*****");
                        BinaryUtil.NVTraceI("binaryHeaderEnum (Byte)", ((Enum)binaryHeaderEnum).ToString());
                        BinaryUtil.NVTraceI("objectId (Int32)", objectId);
                        BinaryUtil.NVTraceI("length (Int32)", lengthA[0]);
                        BCLDebug.Trace("BINARY","****************************");
                        break;
                    default:
                        BCLDebug.Trace("BINARY","*****BinaryArray*****");
                        BinaryUtil.NVTraceI("binaryHeaderEnum (Byte)", ((Enum)binaryHeaderEnum).ToString());
                        BinaryUtil.NVTraceI("objectId (Int32)", objectId);                              
                        BinaryUtil.NVTraceI("binaryArrayTypeEnum (Byte)", ((Enum)binaryArrayTypeEnum).ToString());              
                        BinaryUtil.NVTraceI("rank (Int32)", rank);
                        for (int i=0; i<rank; i++)
                            BinaryUtil.NVTraceI("length (Int32)", lengthA[i]);
                        if ((binaryArrayTypeEnum == BinaryArrayTypeEnum.SingleOffset) ||
                            (binaryArrayTypeEnum == BinaryArrayTypeEnum.JaggedOffset) ||
                            (binaryArrayTypeEnum == BinaryArrayTypeEnum.RectangularOffset))
                        {
                            for (int i=0; i<rank; i++)
                                BinaryUtil.NVTraceI("lowerBound (Int32)", lowerBoundA[i]);
                        }
                        BinaryUtil.NVTraceI("binaryTypeEnum (Byte)", ((Enum)binaryTypeEnum).ToString());
                        if ((binaryTypeEnum == BinaryTypeEnum.Primitive) || 
                            (binaryTypeEnum == BinaryTypeEnum.PrimitiveArray) || 
                            (binaryTypeEnum == BinaryTypeEnum.ObjectUrt) || 
                            (binaryTypeEnum == BinaryTypeEnum.ObjectUser))
                            BinaryUtil.NVTraceI("typeInformation "+BinaryConverter.TypeInfoTraceString(typeInformation), typeInformation);
                        if (binaryTypeEnum == BinaryTypeEnum.ObjectUser)
                            BinaryUtil.NVTraceI("assemId (Int32)", assemId);
                        BCLDebug.Trace("BINARY","****************************");
                        break;
                }
            }
        }
#endif        
    }

    [Serializable]
    public sealed class MemberPrimitiveUnTyped : IStreamable
    {
        // Used for members with primitive values and types are needed

        public InternalPrimitiveTypeE typeInformation;
        public Object value;

        public MemberPrimitiveUnTyped()
        {
        }

        public  void Set(InternalPrimitiveTypeE typeInformation, Object value)
        {
            SerTrace.Log( this, "MemberPrimitiveUnTyped Set typeInformation ",typeInformation," value ",value);
            this.typeInformation = typeInformation;
            this.value = value;
        }

        public  void Set(InternalPrimitiveTypeE typeInformation)
        {
            SerTrace.Log(this, "MemberPrimitiveUnTyped  Set ",typeInformation);
            this.typeInformation = typeInformation;
        }



        public  void Write(__BinaryWriter sout)
        {
            sout.WriteValue(typeInformation, value);
        }

        [System.Security.SecurityCritical] // implements Critical method
        public void Read(__BinaryParser input)
        {
            //binaryHeaderEnum = input.ReadByte(); already read
            value = input.ReadValue(typeInformation);
        }

        public  void Dump()
        {
            DumpInternal();
        }

        [Conditional("_LOGGING")]
        private void DumpInternal()
        {
            //if (BCLDebug.CheckEnabled("BINARY"))
            {
                String typeString = Converter.ToComType(typeInformation);
                BCLDebug.Trace("BINARY","*****MemberPrimitiveUnTyped*****");
                BinaryUtil.NVTraceI("value ("+typeString+")", value);
                BCLDebug.Trace("BINARY","****************************");
            }
        }
    }

    [Serializable]
    public  sealed class MemberReference : IStreamable
    {
        public Int32 idRef;

        public MemberReference()
        {
        }

        public  void Set(Int32 idRef)
        {
            SerTrace.Log( this, "MemberReference Set ",idRef);
            this.idRef = idRef;
        }

        public  void Write(__BinaryWriter sout)
        {
            sout.WriteByte((Byte)BinaryHeaderEnum.MemberReference);
            sout.WriteInt32(idRef);
        }

        [System.Security.SecurityCritical] // implements Critical method
        public void Read(__BinaryParser input)
        {
            //binaryHeaderEnum = input.ReadByte(); already read
            idRef = input.ReadInt32();
        }

        public  void Dump()
        {
            DumpInternal();
        }

        [Conditional("_LOGGING")]
        private void DumpInternal()
        {
            //if (BCLDebug.CheckEnabled("BINARY"))
            {
                BCLDebug.Trace("BINARY","*****MemberReference*****");       
                BinaryUtil.NVTraceI("binaryHeaderEnum (Byte)", ((Enum)BinaryHeaderEnum.MemberReference).ToString());        
                BinaryUtil.NVTraceI("idRef (Int32)", idRef);
                BCLDebug.Trace("BINARY","****************************");
            }
        }
    }

    [Serializable]
    public  sealed class ObjectNull : IStreamable
    {
        public int nullCount;

        public ObjectNull()
        {
        }

        public void SetNullCount(int nullCount)
        {
            this.nullCount = nullCount;
        }

        public  void Write(__BinaryWriter sout)
        {
            if (nullCount == 1)
            {
                sout.WriteByte((Byte)BinaryHeaderEnum.ObjectNull);
            }
            else if (nullCount < 256)
            {
                sout.WriteByte((Byte)BinaryHeaderEnum.ObjectNullMultiple256);
                sout.WriteByte((Byte)nullCount);
                //Console.WriteLine("Write nullCount "+nullCount);
            }
            else
            {
                sout.WriteByte((Byte)BinaryHeaderEnum.ObjectNullMultiple);
                sout.WriteInt32(nullCount);                
                //Console.WriteLine("Write nullCount "+nullCount);
            }
        }


        [System.Security.SecurityCritical] // implements Critical method
        public  void Read(__BinaryParser input)
        {
            Read(input, BinaryHeaderEnum.ObjectNull);
        }

        public  void Read(__BinaryParser input, BinaryHeaderEnum binaryHeaderEnum)
        {
            //binaryHeaderEnum = input.ReadByte(); already read
            switch (binaryHeaderEnum)
            {
                case BinaryHeaderEnum.ObjectNull:
                    nullCount = 1;
                    break;
                case BinaryHeaderEnum.ObjectNullMultiple256:
                    nullCount = input.ReadByte();
                    //Console.WriteLine("Read nullCount "+nullCount);
                    break;
                case BinaryHeaderEnum.ObjectNullMultiple:
                    nullCount = input.ReadInt32();
                    //Console.WriteLine("Read nullCount "+nullCount);
                    break;
            }
        }

        public  void Dump()
        {
            DumpInternal();
        }

        [Conditional("_LOGGING")]
        private void DumpInternal()
        {
            //if (BCLDebug.CheckEnabled("BINARY"))
            {
                BCLDebug.Trace("BINARY","*****ObjectNull*****");
                if (nullCount == 1)
                {
                    BinaryUtil.NVTraceI("binaryHeaderEnum (Byte)", "ObjectNull");
                }
                else if (nullCount < 256)
                {
                    BinaryUtil.NVTraceI("binaryHeaderEnum (Byte)", "ObjectNullMultiple256");
                    BinaryUtil.NVTraceI("nullCount (Byte)", nullCount);
                }
                else
                {
                    BinaryUtil.NVTraceI("binaryHeaderEnum (Byte)", "ObjectNullMultiple");
                    BinaryUtil.NVTraceI("nullCount (Int32)", nullCount);
                }

                BCLDebug.Trace("BINARY","********************");
            }
        }
    }

    [Serializable]
    public sealed class MessageEnd : IStreamable
    {

        public MessageEnd()
        {
        }

        public  void Write(__BinaryWriter sout)
        {
            sout.WriteByte((Byte)BinaryHeaderEnum.MessageEnd);
        }

        [System.Security.SecurityCritical] // implements Critical method
        public void Read(__BinaryParser input)
        {
            //binaryHeaderEnum = input.ReadByte(); already read
        }

        public  void Dump()
        {
            DumpInternal(null);
        }

        public  void Dump(Stream sout)
        {
            DumpInternal(sout);
        }

        [Conditional("_LOGGING")]
        private void DumpInternal(Stream sout)
        {
            //if (BCLDebug.CheckEnabled("BINARY"))
            {
                BCLDebug.Trace("BINARY","*****MessageEnd*****");
                BinaryUtil.NVTraceI("binaryHeaderEnum (Byte)", "MessageEnd");
                long length = -1;
                if (sout != null && sout.CanSeek)
                {
                    length = sout.Length;
                    BinaryUtil.NVTraceI("Total Message Length in Bytes ", length);
                }
                BCLDebug.Trace("BINARY","********************");
            }
        }
    }


    // When an ObjectWithMap or an ObjectWithMapTyped is read off the stream, an ObjectMap class is created
    // to remember the type information. 
    public sealed class ObjectMap
    {
        public String objectName;
        public Type objectType;

        public BinaryTypeEnum[] binaryTypeEnumA;
        public Object[] typeInformationA;
        public Type[] memberTypes;
        public String[] memberNames;
        public ReadObjectInfo objectInfo;
        public bool isInitObjectInfo = true;
        public ObjectReader objectReader = null;
        public Int32 objectId;
        public BinaryAssemblyInfo assemblyInfo;

        [System.Security.SecurityCritical]  // auto-generated
        public ObjectMap(String objectName, Type objectType, String[] memberNames, ObjectReader objectReader, Int32 objectId, BinaryAssemblyInfo assemblyInfo)
        {
            SerTrace.Log( this, "Constructor 1 objectName ",objectName, ", objectType ",objectType);                            
            this.objectName = objectName;
            this.objectType = objectType;
            this.memberNames = memberNames;
            this.objectReader = objectReader;
            this.objectId = objectId;
            this.assemblyInfo = assemblyInfo;

            objectInfo = objectReader.CreateReadObjectInfo(objectType);
            memberTypes = objectInfo.GetMemberTypes(memberNames, objectType); 

            binaryTypeEnumA = new BinaryTypeEnum[memberTypes.Length];
            typeInformationA = new Object[memberTypes.Length];

            for (int i=0; i<memberTypes.Length; i++)
            {
                Object typeInformation = null;
                BinaryTypeEnum binaryTypeEnum = BinaryConverter.GetParserBinaryTypeInfo(memberTypes[i], out typeInformation);
                binaryTypeEnumA[i] = binaryTypeEnum;
                typeInformationA[i] = typeInformation;
            }
        }

        [System.Security.SecurityCritical]  // auto-generated
        public ObjectMap(String objectName, String[] memberNames, BinaryTypeEnum[] binaryTypeEnumA, Object[] typeInformationA, int[] memberAssemIds, ObjectReader objectReader, Int32 objectId, BinaryAssemblyInfo assemblyInfo, SizedArray assemIdToAssemblyTable)
        {
            SerTrace.Log( this, "Constructor 2 objectName ",objectName);
            this.objectName = objectName;
            this.memberNames = memberNames;
            this.binaryTypeEnumA = binaryTypeEnumA;
            this.typeInformationA = typeInformationA;
            this.objectReader = objectReader;
            this.objectId = objectId;
            this.assemblyInfo = assemblyInfo;

            if (assemblyInfo == null)
                throw new SerializationException(Environment.GetResourceString("Serialization_Assembly",objectName));

            objectType = objectReader.GetType(assemblyInfo, objectName);

            memberTypes = new Type[memberNames.Length];

            for (int i=0; i<memberNames.Length; i++)
            {
                InternalPrimitiveTypeE primitiveTypeEnum;
                String typeString;
                Type type;
                bool isVariant;

                BinaryConverter.TypeFromInfo(binaryTypeEnumA[i], typeInformationA[i], objectReader, (BinaryAssemblyInfo)assemIdToAssemblyTable[memberAssemIds[i]],
                                             out primitiveTypeEnum, out typeString, out type, out isVariant);
                //if ((object)type == null)
                //    throw new SerializationException(String.Format(ModifiedVulnerableBinaryFormatters.binary.Environment.GetResourceString("Serialization_TypeResolved"),objectName+" "+memberNames[i]+" "+typeInformationA[i]));
                memberTypes[i] = type;
            }

            objectInfo = objectReader.CreateReadObjectInfo(objectType, memberNames, null);
            if (!objectInfo.isSi)
                objectInfo.GetMemberTypes(memberNames, objectInfo.objectType);  // Check version match
        }

        public ReadObjectInfo CreateObjectInfo(ref SerializationInfo si, ref Object[] memberData)
        {
            if (isInitObjectInfo)
            {
                isInitObjectInfo = false;
                objectInfo.InitDataStore(ref si, ref memberData);
                return objectInfo;
            }
            else
            {
                objectInfo.PrepareForReuse();
                objectInfo.InitDataStore(ref si, ref memberData);
                return objectInfo;
            }
        }


        // No member type information
        [System.Security.SecurityCritical]  // auto-generated
        public static ObjectMap Create(String name, Type objectType, String[] memberNames, ObjectReader objectReader, Int32 objectId, BinaryAssemblyInfo assemblyInfo)
        {
            return new ObjectMap(name, objectType, memberNames, objectReader, objectId, assemblyInfo);
        }

        // Member type information 
        [System.Security.SecurityCritical]  // auto-generated
        public static ObjectMap Create(String name, String[] memberNames, BinaryTypeEnum[] binaryTypeEnumA, Object[] typeInformationA, int[] memberAssemIds, ObjectReader objectReader, Int32 objectId, BinaryAssemblyInfo assemblyInfo, SizedArray assemIdToAssemblyTable)
        {
            return new ObjectMap(name, memberNames, binaryTypeEnumA, typeInformationA, memberAssemIds, objectReader, objectId, assemblyInfo, assemIdToAssemblyTable);           
        }
    }

    // For each object or array being read off the stream, an ObjectProgress object is created. This object
    // keeps track of the progress of the parsing. When an object is being parsed, it keeps track of
    // the object member being parsed. When an array is being parsed it keeps track of the position within the
    // array.
    public sealed class ObjectProgress
    {
        public static int opRecordIdCount = 1;
        public int opRecordId;


        // Control
        public bool isInitial;
        public int count; //Progress count
        public BinaryTypeEnum expectedType = BinaryTypeEnum.ObjectUrt;
        public Object expectedTypeInformation = null;

        public String name;
        public InternalObjectTypeE objectTypeEnum = InternalObjectTypeE.Empty;
        public InternalMemberTypeE memberTypeEnum;
        public InternalMemberValueE memberValueEnum;
        public Type dtType;   

        // Array Information
        public int numItems;
        public BinaryTypeEnum binaryTypeEnum;
        public Object typeInformation;
// disable csharp compiler warning #0414: field assigned unused value
#pragma warning disable 0414
        public int nullCount;
#pragma warning restore 0414

        // Member Information
        public int memberLength;
        public BinaryTypeEnum[] binaryTypeEnumA;
        public Object[] typeInformationA;
        public String[] memberNames;
        public Type[] memberTypes;

        // ParseRecord
        public ParseRecord pr = new ParseRecord();


        public ObjectProgress()
        {
            Counter();
        }

        [Conditional("SER_LOGGING")]                                    
        private void Counter()
        {
            lock(this) {
                opRecordId = opRecordIdCount++;
                if (opRecordIdCount > 1000)
                    opRecordIdCount = 1;
            }
        }

        public void Init()
        {
            isInitial = false;
            count = 0;
            expectedType = BinaryTypeEnum.ObjectUrt;
            expectedTypeInformation = null;

            name = null;
            objectTypeEnum = InternalObjectTypeE.Empty;
            memberTypeEnum = InternalMemberTypeE.Empty;
            memberValueEnum = InternalMemberValueE.Empty;
            dtType = null;  

            // Array Information
            numItems = 0;
            nullCount = 0;
            //binaryTypeEnum
            typeInformation = null;

            // Member Information
            memberLength = 0;
            binaryTypeEnumA = null;
            typeInformationA = null;
            memberNames = null;
            memberTypes = null;

            pr.Init();
        }

        //Array item entry of nulls has a count of nulls represented by that item. The first null has been 
        // incremented by GetNext, the rest of the null counts are incremented here
        public void ArrayCountIncrement(int value)
        {
            count += value;
        }

        // Specifies what is to parsed next from the wire.
        public bool GetNext(out BinaryTypeEnum outBinaryTypeEnum, out Object outTypeInformation)  
        {
            //Initialize the out params up here.
            //<
            outBinaryTypeEnum = BinaryTypeEnum.Primitive;
            outTypeInformation = null;

#if _DEBUG
            SerTrace.Log( this, "GetNext Entry");
            Dump();
#endif

            if (objectTypeEnum == InternalObjectTypeE.Array)
            {
                SerTrace.Log( this, "GetNext Array");                   
                // Array
                if (count == numItems)
                    return false;
                else
                {
                    outBinaryTypeEnum =  binaryTypeEnum;
                    outTypeInformation = typeInformation;
                    if (count == 0)
                        isInitial = false;
                    count++;
                    SerTrace.Log( this, "GetNext Array Exit ",((Enum)outBinaryTypeEnum).ToString()," ",outTypeInformation);                                 
                    return true;
                }
            }
            else
            {
                // Member
                SerTrace.Log( this, "GetNext Member");                              
                if ((count == memberLength) && (!isInitial))
                    return false;
                else
                {
                    outBinaryTypeEnum = binaryTypeEnumA[count];
                    outTypeInformation = typeInformationA[count];
                    if (count == 0)
                        isInitial = false;
                    name = memberNames[count];
                    if (memberTypes == null)
                    {
                        SerTrace.Log( this, "GetNext memberTypes = null");
                    }
                    dtType = memberTypes[count];
                    count++;
                    SerTrace.Log( this, "GetNext Member Exit ",((Enum)outBinaryTypeEnum).ToString()," ",outTypeInformation," memberName ",name);                    
                    return true;
                }
            }
        }

#if _DEBUG
// Get a String describing the ObjectProgress Record
        public  String Trace()
        {
            return "ObjectProgress "+opRecordId+" name "+Util.PString(name)+" expectedType "+((Enum)expectedType).ToString();
        }

        // Dump contents of record

        [Conditional("SER_LOGGING")]                            
        public  void Dump()
        {
            try
            {
                SerTrace.Log("ObjectProgress Dump ");
                Util.NVTrace("opRecordId", opRecordId);
                Util.NVTrace("isInitial", isInitial);
                Util.NVTrace("count", count);
                Util.NVTrace("expectedType", ((Enum)expectedType).ToString());
                Util.NVTrace("expectedTypeInformation", expectedTypeInformation);
                SerTrace.Log("ParseRecord Information");
                Util.NVTrace("name", name);
                Util.NVTrace("objectTypeEnum",((Enum)objectTypeEnum).ToString());
                Util.NVTrace("memberTypeEnum",((Enum)memberTypeEnum).ToString());
                Util.NVTrace("memberValueEnum",((Enum)memberValueEnum).ToString());
                if (dtType != null)
                    Util.NVTrace("dtType", dtType.ToString());
                SerTrace.Log("Array Information");
                Util.NVTrace("numItems", numItems);
                Util.NVTrace("binaryTypeEnum",((Enum)binaryTypeEnum).ToString());
                Util.NVTrace("typeInformation", typeInformation);
                SerTrace.Log("Member Information");
                Util.NVTrace("memberLength", memberLength);
                if (binaryTypeEnumA != null)
                {
                    for (int i=0; i<memberLength; i++)
                        Util.NVTrace("binaryTypeEnumA",((Enum)binaryTypeEnumA[i]).ToString());
                }
                if (typeInformationA != null)
                {
                    for (int i=0; i<memberLength; i++)
                        Util.NVTrace("typeInformationA", typeInformationA[i]);
                }
                if (memberNames != null)
                {
                    for (int i=0; i<memberLength; i++)
                        Util.NVTrace("memberNames", memberNames[i]);
                }
                if (memberTypes != null)
                {
                    for (int i=0; i<memberLength; i++)
                        Util.NVTrace("memberTypes", memberTypes[i].ToString());
                }
            }
            catch (Exception e)
            {
                BCLDebug.Log("[ObjectProgress.Dump]Unable to Dump Object Progress.");
                BCLDebug.Log("[ObjectProgress.Dump]Error: "+e);
            }
        }
#endif 
    }

        }




    
