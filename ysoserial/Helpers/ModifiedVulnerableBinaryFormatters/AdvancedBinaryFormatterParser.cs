using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.Serialization.Formatters;
using System.Runtime.Serialization;
using System.Text;
using System.Text.RegularExpressions;

namespace ysoserial.Helpers.ModifiedVulnerableBinaryFormatters
{
    public class AdvancedBinaryFormatterParser
    {
        public static String StreamToJson(Stream serializationStream)
        {
            return StreamToJson(serializationStream, false, false, true);
        }

        public static String StreamToJson(Stream serializationStream, bool ignoreErrors, bool enableIndent, bool keepInfoFields)
        {
            return AdvancedBinaryFormatterObjectToJson(StreamToAdvancedBinaryFormatterObject(serializationStream, ignoreErrors), enableIndent, keepInfoFields);
        }

        public static List<AdvancedBinaryFormatterObject> StreamToAdvancedBinaryFormatterObject(Stream serializationStream)
        {
            return StreamToAdvancedBinaryFormatterObject(serializationStream, false);
        }

        public static List<AdvancedBinaryFormatterObject> StreamToAdvancedBinaryFormatterObject(Stream serializationStream, bool ignoreErrors)
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

            return serParser.RunModifiedAdvanced(ignoreErrors);
        }
        

        public static MemoryStream AdvancedBinaryFormatterObjectToStream(List<AdvancedBinaryFormatterObject> abfoList)
        {
            MemoryStream resultMS = new MemoryStream();

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

            ObjectWriter objectWriter = new ObjectWriter(m_surrogates, m_context, formatterEnums, m_binder);
            __BinaryWriter binaryWriter = new __BinaryWriter(resultMS, objectWriter, formatterEnums.FEtypeFormat);

            List<int> asmArray = new List<int>();
            foreach (AdvancedBinaryFormatterObject abfo in abfoList)
            {
                var currentObjInfo = abfo.Data;
                if(currentObjInfo.GetType() == typeof(BinaryObjectWithMapTyped))
                {
                    if (currentObjInfo.binaryHeaderEnum == BinaryHeaderEnum.ObjectWithMapTypedAssemId)
                    {
                        if (asmArray.IndexOf(currentObjInfo.assemId) == -1 && currentObjInfo.assemId != 0)
                        {
                            asmArray.Add(currentObjInfo.assemId);
                        }
                        else
                        {
                            currentObjInfo.assemId = 0;
                        }
                    }
                }

                currentObjInfo.Write(binaryWriter);
                if(abfo.ArrayBytes != null)
                {
                    // this is for arrays when we have more data:
                    /*
                     BinaryHeaderEnum.Array:
                     BinaryHeaderEnum.ArraySinglePrimitive:
                     BinaryHeaderEnum.ArraySingleObject:
                     BinaryHeaderEnum.ArraySingleString:
                     */
                    binaryWriter.WriteBytes(abfo.ArrayBytes);

                }
            }
            return resultMS;
        }

        public static MemoryStream JsonToStream(String jsonNet_str)
        {

            String currentNameSpace = typeof(AdvancedBinaryFormatterParser).Namespace;
            String mainAssembly = typeof(AdvancedBinaryFormatterParser).Assembly.GetName().Name;

            String pattern = @"([""']\$type[""']:\s*[""'])([^\""'\.\[\] ,=]+)([\""'])";
            jsonNet_str = Regex.Replace(jsonNet_str, pattern, "$1"+ currentNameSpace + ".$2, " + mainAssembly + "$3");

            List<AdvancedBinaryFormatterObject> deserialized_obj = (List<AdvancedBinaryFormatterObject>)Newtonsoft.Json.JsonConvert.DeserializeObject(jsonNet_str, typeof(List<AdvancedBinaryFormatterObject>), new Newtonsoft.Json.JsonSerializerSettings
            {
                TypeNameHandling = Newtonsoft.Json.TypeNameHandling.Auto
            });

            return AdvancedBinaryFormatterObjectToStream(deserialized_obj);
        }

        public static String AdvancedBinaryFormatterObjectToJson(List<AdvancedBinaryFormatterObject> abfoList)
        {
            return AdvancedBinaryFormatterObjectToJson(abfoList, false, true);
        }

        public static String AdvancedBinaryFormatterObjectToJson(List<AdvancedBinaryFormatterObject> abfoList, bool enableIndent, bool keepInfoFields)
        {
            var defaultFormatting = Newtonsoft.Json.Formatting.None;
            if (enableIndent)
            {
                defaultFormatting = Newtonsoft.Json.Formatting.Indented;
            }

            if (!keepInfoFields)
            {
                foreach(AdvancedBinaryFormatterObject abfo in abfoList)
                {
                    abfo.KeepInfoFieldsForJson = false;
                }
            }

            String jsonNetStr = Newtonsoft.Json.JsonConvert.SerializeObject(abfoList, typeof(List<AdvancedBinaryFormatterObject>), defaultFormatting, new Newtonsoft.Json.JsonSerializerSettings
            {
                TypeNameHandling = Newtonsoft.Json.TypeNameHandling.Auto
            });

            String currentNameSpace = typeof(AdvancedBinaryFormatterParser).Namespace.Replace(".",@"\.");
            String mainAssembly = typeof(AdvancedBinaryFormatterParser).Assembly.GetName().Name.Replace(".", @"\.");

            String pattern = @"(""\$type"":\s*"")" + currentNameSpace + @"\.([^,]+),\s*" + mainAssembly;
            jsonNetStr = Regex.Replace(jsonNetStr, pattern, "$1$2");

            if (enableIndent)
            {
                // removing spaces between array items
                jsonNetStr = Regex.Replace(jsonNetStr, @"\:\s*\[[a-z\sA-Z0-9\,\[\]""'\+\._`]+\],", delegate (Match m) {
                    String finalVal = m.Value;
                    finalVal = Regex.Replace(finalVal, @"\s+", "");
                    return finalVal;
                });

                // removing spaces between non-alphanumerical characters at the beginning of each clause
                jsonNetStr = Regex.Replace(jsonNetStr, @"^\s*([^\w""':. ][^\w""']+)+", delegate (Match m) {
                    String finalVal = m.Value;
                    finalVal = Regex.Replace(finalVal, @"\s+", "");
                    return finalVal;
                }, RegexOptions.Multiline);
            }
            return jsonNetStr;
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
    // The Data property is the only one that matters for serialization/deserialization
    public class AdvancedBinaryFormatterObject
    {
        public AdvancedBinaryFormatterObject() { }

        public AdvancedBinaryFormatterObject(string strType) {
            expectedTypeName = strType;
        }

        // We keep this in serialization so we can easily point to an item - not needed in reconstruction
        public int Id = -1;

        // Not needed in reconstruction but good for information
        public string TypeName = "";

        // Not needed in reconstruction but good for information
        public bool IsPrimitive = false;

        [NonSerialized]
        // This field can be used to minimize the Json.Net output 
        // It will not serialize informational items when it is set to false
        public bool KeepInfoFieldsForJson = true;

        [NonSerialized]
        private dynamic _data;

        // This is for information when debugging
        [NonSerialized]
        public SimpleBinaryFormatterObject simpleBinaryFormatterObject;

        // This is for information when debugging
        [NonSerialized]
        public String expectedTypeName;

        // This is for information when debugging as well as being used during reading a binary formatted object
        [NonSerialized]
        public int ArrayBytesDataRecordLength;

        // this and Data are the only important ones for deserialization really
        public byte[] ArrayBytes;

        // This and ArrayBytes are the only important ones for deserialization really
        public dynamic Data
        {
            get
            {
                return _data;
            }

            set
            {
                //*
                object obj = value;
                using (var ms = new MemoryStream())
                {
                    var formatter = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
                    formatter.Serialize(ms, obj);
                    ms.Position = 0;

                    obj = formatter.Deserialize(ms);
                }
                
                _data = obj;

                //*/
                //_data = ObjectExtensions.Copy(value);
            }
        }

        public bool ShouldSerializeIsPrimitive()
        {
            // don't serialize IsPrimitive when it is not primitive or when KeepInfoFieldsForJson == false
            return (IsPrimitive && KeepInfoFieldsForJson);
        }

        public bool ShouldSerializeArrayBytes()
        {
            // don't serialize IsPrimitive when it is not primitive or when KeepInfoFieldsForJson == false
            return (ArrayBytes != null);
        }

        public bool ShouldSerializeTypeName()
        {
            // don't serialize IsPrimitive when it is not primitive or when KeepInfoFieldsForJson == false
            return (!String.IsNullOrEmpty(TypeName) && KeepInfoFieldsForJson);
        }

        public bool ShouldSerializeId()
        {
            // don't serialize Id when KeepInfoFieldsForJson == false
            return (KeepInfoFieldsForJson);
        }

        public AdvancedBinaryFormatterObject DeepClone()
        {
            AdvancedBinaryFormatterObject newAbfo = new AdvancedBinaryFormatterObject();

            newAbfo.Data = this.Data;
            newAbfo.expectedTypeName = this.expectedTypeName;
            newAbfo.Id = this.Id;
            newAbfo.IsPrimitive = this.IsPrimitive;
            newAbfo.simpleBinaryFormatterObject = this.simpleBinaryFormatterObject;
            newAbfo.TypeName = this.TypeName;
            newAbfo.ArrayBytes = this.ArrayBytes;
            newAbfo.ArrayBytesDataRecordLength = this.ArrayBytesDataRecordLength;
            return newAbfo;
        }

    }
}
