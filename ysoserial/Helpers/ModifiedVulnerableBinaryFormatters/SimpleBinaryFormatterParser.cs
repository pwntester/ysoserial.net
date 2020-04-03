using System;
using System.IO;
using System.Reflection;
using System.Globalization;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.Serialization.Formatters;
using System.Runtime.Remoting;
using System.Runtime.Remoting.Messaging;

using System.Runtime.Serialization;
using System.Security.Permissions;
using System.Diagnostics.Contracts;
using System.Collections.Concurrent;
using System.Text;
using System.Web.Script.Serialization;

namespace ysoserial.Helpers.ModifiedVulnerableBinaryFormatters
{
    public class SimpleBinaryFormatterParser
    {
        public static BinaryFormatterRootObject Parse(Stream serializationStream)
        {
            if (serializationStream.CanRead)
                serializationStream.Position = 0;

            InternalFE formatterEnums = new InternalFE();
            formatterEnums.FEtypeFormat = FormatterTypeStyle.TypesAlways;
            formatterEnums.FEserializerTypeEnum = InternalSerializerTypeE.Binary;
            formatterEnums.FEassemblyFormat = FormatterAssemblyStyle.Simple;
            formatterEnums.FEsecurityLevel = TypeFilterLevel.Low;
            ISurrogateSelector m_surrogates = null;
            StreamingContext m_context = new StreamingContext(StreamingContextStates.All);
            SerializationBinder m_binder = null;
            //bool fCheck = false;
            //HeaderHandler handler = null;

            ObjectReader objectReader = new ObjectReader(serializationStream, m_surrogates, m_context, formatterEnums, m_binder);
            __BinaryParser serParser = new __BinaryParser(serializationStream, objectReader);
            //BinaryReader dataReader = new BinaryReader(serializationStream, new UTF8Encoding(false, true));

            return serParser.RunModified();
        }

        public static MemoryStream ReconstructFromBinaryFormatterObject(BinaryFormatterRootObject inBinaryFormatterRootObject)
        {
            int fullsize = CalculateSizeOfbfObject(inBinaryFormatterRootObject);

            MemoryStream ms = new MemoryStream(fullsize);

            ms.Write(inBinaryFormatterRootObject.headerBytes, 0, inBinaryFormatterRootObject.headerBytes.Length);
            foreach (BinaryFormatterObject bfObj in inBinaryFormatterRootObject.binaryFormatterObjects)
            {
                if (bfObj.typeBytes != null)
                    ms.Write(bfObj.typeBytes, 0, bfObj.typeBytes.Length);

                if (bfObj.valueBytes != null)
                    ms.Write(bfObj.valueBytes, 0, bfObj.valueBytes.Length);
            }
            return ms;
        }

        public static MemoryStream ReconstructFromJsonNetSerializedBinaryFormatterObject(String jsonNet_str)
        {
            BinaryFormatterRootObject deserialized_obj = (BinaryFormatterRootObject)Newtonsoft.Json.JsonConvert.DeserializeObject(jsonNet_str, typeof(BinaryFormatterRootObject));
            return ReconstructFromBinaryFormatterObject(deserialized_obj);
        }

        public static String JsonNetBinaryFormatterObjectSerializer(BinaryFormatterRootObject inBinaryFormatterRootObject)
        {
            return Newtonsoft.Json.JsonConvert.SerializeObject(inBinaryFormatterRootObject, typeof(Helpers.ModifiedVulnerableBinaryFormatters.BinaryFormatterRootObject), null);
        }

        public static int CalculateSizeOfbfObject(BinaryFormatterRootObject inBinaryFormatterRootObject)
        {
            int size = 17; // fized header size

            foreach (BinaryFormatterObject bfObj in inBinaryFormatterRootObject.binaryFormatterObjects)
            {
                if (bfObj.typeBytes != null)
                    size += bfObj.typeBytes.Length;

                if (bfObj.valueBytes != null)
                    size += bfObj.valueBytes.Length;
            }

            return size;
        }

        public static byte[] Calculate7BitEncodedInt(int value)
        {
            // it cannot be more than 5 bytes according to [MS-NRBF]
            byte[] output = new byte[1];
            // Similar to Write7BitEncodedInt from System.IO.BinaryWriter
            uint v = (uint)value;
            int counter = 0;

            while (v >= 0x80)
            {
                if (counter > 1)
                    Array.Resize(ref output, counter + 1);

                output[counter] = ((byte)(v | 0x80));
                v >>= 7;
                counter++;
            }

            if (counter > 0)
                Array.Resize(ref output, counter + 1);

            output[counter] = ((byte)v);

            return output;
        }

        public static byte[] Create7bitLengthObjectString(string strInput)
        {
            byte[] size = Calculate7BitEncodedInt(strInput.Length);
            byte[] value = Encoding.UTF8.GetBytes(strInput);
            return ConcatTwoByteArrays(size, value);
        }

        public static byte[] ConcatTwoByteArrays(byte[] arr1, byte[] arr2)
        {
            byte[] result = new byte[arr1.Length + arr2.Length];
            Array.Copy(arr1, 0, result, 0, arr1.Length);
            Array.Copy(arr2, 0, result, arr1.Length, arr2.Length);
            return result;
        }
    }
    [Serializable]
    public class BinaryFormatterRootObject
    {
        public BinaryFormatterRootObject() { }

        // Needed in reconstruction although should be always fixed
        public byte[] headerBytes = new byte[17];

        // This is for information especially when debugging
        [NonSerialized]
        public int size = -1;

        // Needed in reconstruction
        public List<BinaryFormatterObject> binaryFormatterObjects = new List<BinaryFormatterObject>();

        // This is for information especially when debugging
        [NonSerialized]
        public String expectedTypeName;
    }

    [Serializable]
    public class BinaryFormatterObject
    {
        public BinaryFormatterObject() { }

        // We keep this in serialization so we can easily point to an item - not needed in reconstruction
        public int orderId = -1;

        // This is for information especially when debugging
        [NonSerialized]
        public int valueSize = -1;

        // Needed in reconstruction
        public byte[] typeBytes; // it should be just one type but this is for simplicity

        // Needed in reconstruction
        public byte[] valueBytes;

        // This is for information especially when debugging
        [NonSerialized]
        public string valueString;

        // This is for information especially when debugging
        [NonSerialized]
        public String typeName;
    }

}
