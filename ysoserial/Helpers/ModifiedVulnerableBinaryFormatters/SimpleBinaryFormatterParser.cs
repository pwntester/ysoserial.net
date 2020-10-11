using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.Serialization.Formatters;
using System.Runtime.Serialization;
using System.Text;

namespace ysoserial.Helpers.ModifiedVulnerableBinaryFormatters
{
    // Always use AdvancedBinaryFormatterParser wherever possible as this one is not as readable and is only a quick fix for when we desperately need to create a serialized object very fast!
    public class SimpleBinaryFormatterParser
    {
        public static SimpleBinaryFormatterRootObject StreamToSimpleBinaryFormatterRootObject(Stream serializationStream)
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

        public static MemoryStream SimpleBinaryFormatterRootObjectToStream(SimpleBinaryFormatterRootObject inBinaryFormatterRootObject)
        {
            int fullsize = CalculateSizeOfbfObject(inBinaryFormatterRootObject);

            MemoryStream ms = new MemoryStream(fullsize);

            ms.Write(inBinaryFormatterRootObject.headerBytes, 0, inBinaryFormatterRootObject.headerBytes.Length);
            foreach (SimpleBinaryFormatterObject bfObj in inBinaryFormatterRootObject.binaryFormatterObjects)
            {
                if (bfObj.typeBytes != null)
                    ms.Write(bfObj.typeBytes, 0, bfObj.typeBytes.Length);

                if (bfObj.valueBytes != null)
                    ms.Write(bfObj.valueBytes, 0, bfObj.valueBytes.Length);
            }
            return ms;
        }

        public static MemoryStream JsonToStream(String jsonNet_str)
        {
            SimpleBinaryFormatterRootObject deserialized_obj = (SimpleBinaryFormatterRootObject)Newtonsoft.Json.JsonConvert.DeserializeObject(jsonNet_str, typeof(SimpleBinaryFormatterRootObject));
            return SimpleBinaryFormatterRootObjectToStream(deserialized_obj);
        }

        public static String SimpleBinaryFormatterRootObjectToJson(SimpleBinaryFormatterRootObject inBinaryFormatterRootObject)
        {
            return Newtonsoft.Json.JsonConvert.SerializeObject(inBinaryFormatterRootObject, typeof(Helpers.ModifiedVulnerableBinaryFormatters.SimpleBinaryFormatterRootObject), null);
        }

        public static int CalculateSizeOfbfObject(SimpleBinaryFormatterRootObject inBinaryFormatterRootObject)
        {
            int size = 17; // fized header size

            foreach (SimpleBinaryFormatterObject bfObj in inBinaryFormatterRootObject.binaryFormatterObjects)
            {
                if (bfObj.typeBytes != null)
                    size += bfObj.typeBytes.Length;

                if (bfObj.valueBytes != null)
                    size += bfObj.valueBytes.Length;
            }

            return size;
        }

        // This was buggy so it was replaced:
        /*
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
        */
        // Thanks to a previously submitted code by Dane Evans
        public static byte[] Calculate7BitEncodedInt(int value)
        {
            List<byte> bytes = new List<byte>();

            uint num;
            for (num = (uint)value; num >= 128U; num >>= 7)
            {
                bytes.Add((byte)(num | 128U));
            }

            bytes.Add((byte)num);
            return bytes.ToArray();
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
    public class SimpleBinaryFormatterRootObject
    {
        public SimpleBinaryFormatterRootObject() { }

        // Needed in reconstruction although should be always fixed
        public byte[] headerBytes = new byte[17];

        // This is for information when debugging
        [NonSerialized]
        public int size = -1;

        // Needed in reconstruction
        public List<SimpleBinaryFormatterObject> binaryFormatterObjects = new List<SimpleBinaryFormatterObject>();
    }

    [Serializable]
    public class SimpleBinaryFormatterObject
    {
        public SimpleBinaryFormatterObject() { }

        // We keep this in serialization so we can easily point to an item - not needed in reconstruction
        public int orderId = -1;

        // This is for information when debugging
        [NonSerialized]
        public int valueSize = -1;

        // Needed in reconstruction
        public byte[] typeBytes; // it should be just one type but this is for simplicity

        // Needed in reconstruction
        public byte[] valueBytes;

        // This is for information when debugging
        [NonSerialized]
        public string valueString;

        // This is for information when debugging
        [NonSerialized]
        public String typeName;

        // This is for information when debugging
        [NonSerialized]
        public String expectedTypeName;

        // This is for information when debugging
        [NonSerialized]
        public int origStreamStartPosition;

        // This is for information when debugging
        [NonSerialized]
        public int origStreamEndPosition;
    }

}
