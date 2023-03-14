using MessagePack;
using MessagePack.Resolvers;
using Newtonsoft.Json;
using Polenter.Serialization;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Runtime.Serialization.Formatters.Soap;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;
using System.Web.UI;
using System.Windows.Documents;
using System.Windows.Markup;
using System.Xml;
using System.Xml.Serialization;
using YamlDotNet.Serialization;
using ysoserial.Helpers.ModifiedVulnerableBinaryFormatters;

namespace ysoserial.Helpers
{
    public class SerializersHelper
    {
        public static void ShowAll(object myobj)
        {
            ShowAll(myobj, myobj.GetType());
        }

        public static void ShowAll(object myobj, Type type)
        {
            try
            {
                Console.WriteLine("\n~~XmlSerializer:~~\n");
                Console.WriteLine(XmlSerializer_serialize(myobj, myobj.GetType()));
            }
            catch (Exception e)
            {
                Console.WriteLine("\tError in XmlSerializer!");
            }

            try
            {
                Console.WriteLine("\n~~DataContractSerializer:~~\n");
                Console.WriteLine(DataContractSerializer_serialize(myobj, myobj.GetType()));
            }
            catch (Exception e)
            {
                Console.WriteLine("\tError in DataContractSerializer!");
            }

            try
            {
                Console.WriteLine("\n~~Xaml:~~\n");
                Console.WriteLine(Xaml_serialize(myobj));
            }
            catch (Exception e)
            {
                Console.WriteLine("\tError in Xaml!");
            }


            try
            {
                Console.WriteLine("\n~~NetDataContractSerializer:~~\n");
                Console.WriteLine(NetDataContractSerializer_serialize(myobj));
            }
            catch (Exception e)
            {
                Console.WriteLine("\tError in NetDataContractSerializer!");
            }

            try
            {
                Console.WriteLine("\n~~JSON.NET:~~\n");
                Console.WriteLine(JsonNet_serialize(myobj));
            }
            catch (Exception e)
            {
                Console.WriteLine("\tError in JSON.NET!");
            }

            try
            {
                Console.WriteLine("\n~~SoapFormatter:~~\n");
                Console.WriteLine(SoapFormatter_serialize(myobj));
            }
            catch (Exception e)
            {
                Console.WriteLine("\tError in SoapFormatter!");
            }

            try
            {
                Console.WriteLine("\n~~BinaryFormatter:~~\n");
                Console.WriteLine(BinaryFormatter_serialize_ToBase64(myobj));
            }
            catch (Exception e)
            {
                Console.WriteLine("\tError in BinaryFormatter!");
            }

            try
            {
                Console.WriteLine("\n~~LosFormatter:~~\n");
                Console.WriteLine(LosFormatter_serialize(myobj));
            }
            catch (Exception e)
            {
                Console.WriteLine("\tError in LosFormatter!");
            }

            try
            {
                Console.WriteLine("\n~~ObjectStateFormatter:~~\n");
                Console.WriteLine(ObjectStateFormatter_serialize(myobj));
            }
            catch (Exception e)
            {
                Console.WriteLine("\tError in ObjectStateFormatter!");
            }

            try
            {
                Console.WriteLine("\n~~YamlDotNet:~~\n");
                Console.WriteLine(YamlDotNet_serialize(myobj));
            }
            catch (Exception e)
            {
                Console.WriteLine("\tError in YamlDotNet!");
            }

            try
            {
                Console.WriteLine("\n~~JavaScriptSerializer:~~\n");
                Console.WriteLine(JavaScriptSerializer_serialize(myobj));
            }
            catch (Exception e)
            {
                Console.WriteLine("\tError in JavaScriptSerializer!");
            }

            try
            {
                Console.WriteLine("\n~~SharpSerializer (Binary):~~\n");
                Console.WriteLine(SharpSerializer_Binary_serialize_ToBase64(myobj));
            }
            catch (Exception e)
            {
                Console.WriteLine("\tError in SharpSerializer (Binary)!");
            }

            try
            {
                Console.WriteLine("\n~~SharpSerializer (XML):~~\n");
                Console.WriteLine(SharpSerializer_Xml_serialize_ToString(myobj));
            }
            catch (Exception e)
            {
                Console.WriteLine("\tError in SharpSerializer (XML)!");
            }

            try
            {
                Console.WriteLine("\n~~MessagePackTypeless:~~\n");
                Console.WriteLine(MessagePackTypeless_serialize_ToBase64(myobj));
            }
            catch (Exception e)
            {
                Console.WriteLine("\tError in MessagePackTypeless!");
            }

            try
            {
                Console.WriteLine("\n~~MessagePackTypeless (Lz4):~~\n");
                Console.WriteLine(MessagePackTypeless_Lz4_serialize_ToBase64(myobj));
            }
            catch (Exception e)
            {
                Console.WriteLine("\tError in MessagePackTypeless (Lz4)!");
            }
        }

        public static void TestAll(object myobj)
        {
            TestAll(myobj, myobj.GetType(), null);
        }

        public static void TestAll(object myobj, Type type, Type[] knownTypes)
        {
            // knownTypes is used in DataContractJsonSerializer_test

            StringBuilder sb = new StringBuilder();
            sb.Append("Object returned from:");
            if (XmlSerializer_test(myobj, type) != null)
            {
                sb.AppendLine("XmlSerializer_test");
            }
            if (DataContractSerializer_test(myobj, type) != null)
            {
                sb.AppendLine("DataContractSerializer_test");
            }
            if (Xaml_test(myobj) != null)
            {
                sb.AppendLine("Xaml_test");
            }
            if (NetDataContractSerializer_test(myobj) != null)
            {
                sb.AppendLine("NetDataContractSerializer_test");
            }
            if (JsonNet_test(myobj) != null)
            {
                sb.AppendLine("JsonNet_test");
            }
            if (SoapFormatter_test(myobj) != null)
            {
                sb.AppendLine("SoapFormatter_test");
            }
            if (BinaryFormatter_test(myobj) != null)
            {
                sb.AppendLine("BinaryFormatter_test");
            }
            if (LosFormatter_test(myobj) != null)
            {
                sb.AppendLine("LosFormatter_test");
            }
            if (ObjectStateFormatter_test(myobj) != null)
            {
                sb.AppendLine("ObjectStateFormatter_test");
            }
            if (YamlDotNet_test(myobj) != null)
            {
                sb.AppendLine("YamlDotNet_test");
            }
            if (JavaScriptSerializer_test(myobj) != null)
            {
                sb.AppendLine("JavaScriptSerializer_test");
            }
            if (DataContractJsonSerializer_test(myobj, type, knownTypes) != null)
            {
                sb.AppendLine("DataContractJsonSerializer_test");
            }
            if (SharpSerializer_Binary_test(myobj) != null)
            {
                sb.AppendLine("SharpSerializer_ObjectDataProvider_Binary_test");
            }
            if (SharpSerializer_Xml_test(myobj) != null)
            {
                sb.AppendLine("SharpSerializer_ObjectDataProvider_Xml_test");
            }
            if (MessagePackTypeless_test(myobj) != null)
            {
                sb.AppendLine("MessagePackTypeless_test");
            }
            if (MessagePackTypelessLz4_test(myobj) != null)
            {
                sb.AppendLine("MessagePackTypelessLz4_test");
            }
            Console.WriteLine(sb);
        }

        public static object XmlSerializer_test(object myobj)
        {
            try
            {
                return XmlSerializer_deserialize(XmlSerializer_serialize(myobj), myobj.GetType());
            }
            catch (Exception e)
            {
                //ignore
                return null;
            }
        }

        public static object XmlSerializer_test(object myobj, Type type)
        {
            try
            {
                return XmlSerializer_deserialize(XmlSerializer_serialize(myobj, type), type);
            }
            catch (Exception e)
            {
                //ignore
                return null;
            }
        }

        public static string XmlSerializer_serialize(object myobj)
        {
            return XmlSerializer_serialize(myobj, myobj.GetType());
        }

        public static string XmlSerializer_serialize(object myobj, Type type)
        {
            XmlSerializer xmlSerializer = new XmlSerializer(type);
            TextWriter stringWriter = new StringWriter(CultureInfo.InvariantCulture);
            xmlSerializer.Serialize(stringWriter, myobj);
            string text = stringWriter.ToString();
            stringWriter.Close();
            return text;
        }

        public static object XmlSerializer_deserialize(string str, string type)
        {
            return XmlSerializer_deserialize(str, type, "", "");
        }

        public static object XmlSerializer_deserialize(string str, string type, string rootElement, string typeAttributeName)
        {
            object obj = null;

            if (!rootElement.Equals(""))
            {
                var xmlDoc = new XmlDocument();
                xmlDoc.LoadXml(str);
                XmlElement xmlItem = (XmlElement)xmlDoc.SelectSingleNode(rootElement);
                if (string.IsNullOrEmpty(typeAttributeName))
                {
                    typeAttributeName = "type";
                }
                var s = new XmlSerializer(Type.GetType(xmlItem.GetAttribute(typeAttributeName)));
                obj = s.Deserialize(new XmlTextReader(new StringReader(xmlItem.InnerXml)));
            }
            else
            {
                var s = new XmlSerializer(Type.GetType(type));
                obj = s.Deserialize(new XmlTextReader(new StringReader(str)));
            }

            return obj;
        }

        public static object XmlSerializer_deserialize(string str, Type type)
        {
            var s = new XmlSerializer(type);
            object obj = s.Deserialize(new XmlTextReader(new StringReader(str)));
            return obj;
        }

        // This to replace our bespoked marshal objects with the actual object
        // Example: when we use DataContractSerializer_serialize for TextFormattingRunPropertiesMarshal
        // it will add the rootTagName when rootTagName is not empty 
        // default for typeAttributeName is type
        public static string DataContractSerializer_Marshal_2_MainType(string dirtymarshal)
        {
            return DataContractSerializer_Marshal_2_MainType(dirtymarshal, "", "", null);
        }

        public static string DataContractSerializer_Marshal_2_MainType(string dirtymarshal, string rootTagName, string typeAttributeName, Type objectType)
        {
            string result = "";

            // Finding the namespace tag prefix of "http://schemas.microsoft.com/2003/10/Serialization/"
            Regex tagPrefixSerializationRegex = new Regex(@"xmlns:([\w]+)\s*=\s*""http://schemas.microsoft.com/2003/10/Serialization/""", RegexOptions.IgnoreCase);
            Match tagPrefixSerializationMatch = tagPrefixSerializationRegex.Match(dirtymarshal);
            if (tagPrefixSerializationMatch.Groups.Count > 1)
            {
                string tagPrefixSerialization = tagPrefixSerializationMatch.Groups[1].Value;
                if (!string.IsNullOrEmpty(tagPrefixSerialization))
                {
                    // Finding the main type using tagPrefixSerialization:FactoryType
                    Regex regexFactoryType = new Regex(tagPrefixSerialization + @":FactoryType\s*=\s*""([^:]+):([^""]+)""", RegexOptions.IgnoreCase);
                    Match matchFactoryType = regexFactoryType.Match(dirtymarshal);
                    if (matchFactoryType.Groups.Count > 2)
                    {
                        string factoryTypeFullString = matchFactoryType.Groups[0].Value;
                        string mainTypeTagPrefix = matchFactoryType.Groups[1].Value;
                        string mainTypeTagName = matchFactoryType.Groups[2].Value;
                        if (!string.IsNullOrEmpty(mainTypeTagName) && !string.IsNullOrEmpty(mainTypeTagPrefix))
                        {
                            // start replacing the dirty bits!

                            // we need to remove <?xml at the beginning if there is any
                            result = Regex.Replace(dirtymarshal, @"\s*\<\?xml[^\>]+\?\>", "", RegexOptions.IgnoreCase);
                            // removing spaces in front of the lines
                            result = Regex.Replace(result, @"^\s+", "");

                            Regex regexMarshaledTagName = new Regex(@"^\s*<([^\s>]+)");
                            Match matchMarshaledTagName = regexMarshaledTagName.Match(result);
                            string marshaledTagName = matchMarshaledTagName.Groups[1].Value;
                            result = result.Replace(marshaledTagName, mainTypeTagName); // replacing the marshaled tag with the main tag
                            result = result.Replace(factoryTypeFullString, ""); // removing FactoryType bit
                            result = Regex.Replace(result, @"(?<=\<" + mainTypeTagName + @"[^>]+)\s+xmlns=""http://schemas.datacontract.org/[^""]+""", ""); // removing current namespace
                            result = result.Replace(":" + mainTypeTagPrefix, ""); // creating the new namespace

                            if (!string.IsNullOrEmpty(rootTagName) && objectType != null)
                            {
                                // adding the root type
                                if (string.IsNullOrEmpty(typeAttributeName))
                                {
                                    typeAttributeName = "type";
                                }

                                // we need this to make it standard
                                result = XmlHelper.XmlXSLTMinifier(dirtymarshal);

                                result = "<" + rootTagName + " " + typeAttributeName + @"=""" + objectType.AssemblyQualifiedName + @""">" + result + "</" + rootTagName + ">";
                            }

                        }
                    }

                }
            }

            return result;
        }

        public static object DataContractSerializer_test(object myobj)
        {
            return DataContractSerializer_deserialize(DataContractSerializer_serialize(myobj), myobj.GetType());
        }

        public static object DataContractSerializer_test(object myobj, Type type)
        {
            return DataContractSerializer_test(myobj, type, null);
        }

        public static object DataContractSerializer_test(object myobj, Type type, Type[] knownTypes)
        {
            try
            {
                return DataContractSerializer_deserialize(DataContractSerializer_serialize(myobj, type, knownTypes), type, knownTypes);
            }
            catch (Exception e)
            {
                //ignore
                return null;
            }
        }

        public static string DataContractSerializer_serialize(object myobj)
        {
            return DataContractSerializer_serialize(myobj, myobj.GetType());
        }

        public static string DataContractSerializer_serialize(object myobj, Type type)
        {
            return DataContractSerializer_serialize(myobj, type, null);
        }

        public static string DataContractSerializer_serialize(object myobj, Type type, Type[] knownTypes)
        {
            XmlWriterSettings settings = new XmlWriterSettings();
            settings.Indent = true;
            StringBuilder sb = new StringBuilder();
            using (XmlWriter writer = XmlWriter.Create(sb, settings))
            {
                DataContractSerializer ser = new DataContractSerializer(type, knownTypes);
                ser.WriteObject(writer, myobj);
            }
            string text = sb.ToString();
            return text;
        }

        public static object DataContractSerializer_deserialize(string str, string type)
        {
            return DataContractSerializer_deserialize(str, type, "", "");
        }

        public static object DataContractSerializer_deserialize(string str, string type, string rootElement, string typeAttributeName)
        {
            object obj = null;

            if (!rootElement.Equals(""))
            {
                var xmlDoc = new XmlDocument();
                xmlDoc.LoadXml(str);
                XmlElement xmlItem = (XmlElement)xmlDoc.SelectSingleNode(rootElement);
                if (string.IsNullOrEmpty(typeAttributeName))
                {
                    typeAttributeName = "type";
                }
                var s = new DataContractSerializer(Type.GetType(xmlItem.GetAttribute(typeAttributeName)));
                obj = s.ReadObject(new XmlTextReader(new StringReader(xmlItem.InnerXml)));
            }
            else
            {
                var s = new DataContractSerializer(Type.GetType(type));
                obj = s.ReadObject(new XmlTextReader(new StringReader(str)));
            }
            return obj;
        }

        public static object DataContractSerializer_deserialize(string str, Type type)
        {
            return DataContractSerializer_deserialize(str, type, null);
        }

        public static object DataContractSerializer_deserialize(string str, Type type, Type[] knownTypes)
        {
            var s = new DataContractSerializer(type, knownTypes);
            object obj = s.ReadObject(new XmlTextReader(new StringReader(str)));
            return obj;
        }



        public static object Xaml_test(object myobj)
        {
            try
            {
                return Xaml_deserialize(Xaml_serialize(myobj));
            }
            catch (Exception e)
            {
                //ignore
                return null;
            }
        }

        public static string Xaml_serialize(object myobj)
        {
            // return XamlWriter.Save(myobj); // we lose indentation here so:
            XmlWriterSettings settings = new XmlWriterSettings();
            settings.Indent = true;
            StringBuilder sb = new StringBuilder();

            using (XmlWriter writer = XmlWriter.Create(sb, settings))
            {
                System.Windows.Markup.XamlWriter.Save(myobj, writer);
            }

            string text = sb.ToString();
            return text;
        }

        public static object Xaml_deserialize(string str)
        {
            object obj = XamlReader.Load(new XmlTextReader(new StringReader(str)));
            return obj;
        }

        // This to replace our bespoked marshal objects with the actual object
        // Example: when we use NetDataContractSerializer_serialize for TextFormattingRunPropertiesMarshal
        public static string NetDataContractSerializer_Marshal_2_MainType(string dirtymarshal)
        {
            return DataContractSerializer_Marshal_2_MainType(dirtymarshal);
        }

        public static object NetDataContractSerializer_test(object myobj)
        {
            try
            {
                return NetDataContractSerializer_deserialize(NetDataContractSerializer_serialize(myobj));
            }
            catch (Exception e)
            {
                //ignore
                return null;
            }
        }

        public static string NetDataContractSerializer_serialize(object myobj)
        {
            XmlWriterSettings settings = new XmlWriterSettings();
            settings.Indent = true;
            StringBuilder sb = new StringBuilder();
            using (XmlWriter writer = XmlWriter.Create(sb, settings))
            {
                NetDataContractSerializer ser = new NetDataContractSerializer();
                ser.WriteObject(writer, myobj);
            }
            string text = sb.ToString();
            return text;
        }

        public static object NetDataContractSerializer_deserialize(string str)
        {
            return NetDataContractSerializer_deserialize(str, "");
        }

        public static object NetDataContractSerializer_deserialize(string str, string rootElement)
        {
            object obj = null;
            var s = new NetDataContractSerializer();
            if (!rootElement.Equals(""))
            {
                var xmlDoc = new XmlDocument() { XmlResolver = null };
                xmlDoc.LoadXml(str);
                XmlElement xmlItem = (XmlElement)xmlDoc.SelectSingleNode(rootElement);
                obj = s.ReadObject(new XmlTextReader(new StringReader(xmlItem.InnerXml)));
            }
            else
            {
                byte[] serializedData = Encoding.UTF8.GetBytes(str);
                MemoryStream ms = new MemoryStream(serializedData);
                obj = s.Deserialize(ms);
            }

            return obj;
        }

        public static object JsonNet_test(object myobj)
        {
            try
            {
                return JsonNet_deserialize(JsonNet_serialize(myobj));
            }
            catch (Exception e)
            {
                //ignore
                return null;
            }
        }

        public static string JsonNet_serialize(object myobj)
        {
            string text = JsonConvert.SerializeObject(myobj, new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.Auto
            });
            return text;
        }

        public static object JsonNet_deserialize(string str)
        {
            Object obj = JsonConvert.DeserializeObject<Object>(str, new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.Auto
            });
            return obj;
        }

        public static object SoapFormatter_test(object myobj)
        {
            try
            {
                return SoapFormatter_deserialize(SoapFormatter_serialize(myobj));
            }
            catch (Exception e)
            {
                //ignore
                return null;
            }
        }

        public static string SoapFormatter_serialize(object myobj)
        {
            SoapFormatter sf = new SoapFormatter();
            MemoryStream ms = new MemoryStream();
            sf.Serialize(ms, myobj);
            return Encoding.ASCII.GetString(ms.ToArray());
        }

        public static object SoapFormatter_deserialize(string str)
        {
            byte[] byteArray = System.Text.Encoding.ASCII.GetBytes(str);
            MemoryStream ms = new MemoryStream(byteArray);
            SoapFormatter sf = new SoapFormatter();
            return sf.Deserialize(ms);
        }

        public static object BinaryFormatter_test(object myobj)
        {
            try
            {
                return BinaryFormatter_deserialize_FromBase64(BinaryFormatter_serialize_ToBase64(myobj));
            }
            catch (Exception e)
            {
                //ignore
                return null;
            }
        }

        public static string BinaryFormatter_serialize_ToJson(object myobj)
        {
            return AdvancedBinaryFormatterParser.StreamToJson(BinaryFormatter_serialize_ToMemoryStream(myobj), false, true, true);
        }

        public static string BinaryFormatter_serialize_ToBase64(object myobj)
        {
            return Convert.ToBase64String(BinaryFormatter_serialize_ToMemoryStream(myobj).ToArray());
        }

        public static byte[] BinaryFormatter_serialize_ToByteArray(object myobj)
        {
            return BinaryFormatter_serialize_ToMemoryStream(myobj).ToArray();
        }

        public static MemoryStream BinaryFormatter_serialize_ToMemoryStream(object myobj)
        {
            System.Runtime.Serialization.Formatters.Binary.BinaryFormatter bf = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
            MemoryStream ms = new MemoryStream();
            bf.Serialize(ms, myobj);
            ms.Position = 0;
            return ms;
        }

        public static object BinaryFormatter_deserialize_FromBase64(string str)
        {
            byte[] byteArray = Convert.FromBase64String(str);
            MemoryStream ms = new MemoryStream(byteArray);
            return BinaryFormatter_deserialize(ms);
        }

        public static object BinaryFormatter_deserialize(byte[] byteArray)
        {
            MemoryStream ms = new MemoryStream(byteArray);
            return BinaryFormatter_deserialize(ms);
        }

        public static object BinaryFormatter_deserialize(MemoryStream ms)
        {
            ms.Position = 0;
            System.Runtime.Serialization.Formatters.Binary.BinaryFormatter bf = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
            return bf.Deserialize(ms);
        }

        public static object LosFormatter_test(object myobj)
        {
            try
            {
                return LosFormatter_deserialize(LosFormatter_serialize(myobj));
            }
            catch (Exception e)
            {
                //ignore
                return null;
            }
        }

        public static string LosFormatter_serialize(object myobj)
        {
            StringWriter s = new StringWriter(CultureInfo.InvariantCulture);
            new LosFormatter().Serialize(s, myobj);

            return s.ToString();
        }

        public static object LosFormatter_deserialize(string str)
        {
            return new LosFormatter().Deserialize(str);
        }

        public static object LosFormatter_deserialize(byte[] byt)
        {
            return new LosFormatter().Deserialize(Encoding.UTF8.GetString(byt));
        }

        public static object ObjectStateFormatter_test(object myobj)
        {
            try
            {
                return ObjectStateFormatter_deserialize(ObjectStateFormatter_serialize(myobj));
            }
            catch (Exception e)
            {
                //ignore
                return null;
            }
        }

        public static string ObjectStateFormatter_serialize(object myobj)
        {
            return new ObjectStateFormatter().Serialize(myobj);
        }

        public static object ObjectStateFormatter_deserialize(string str)
        {
            return new ObjectStateFormatter().Deserialize(str);
        }

        public static object YamlDotNet_test(object myobj)
        {
            try
            {
                return YamlDotNet_deserialize(YamlDotNet_serialize(myobj));
            }
            catch (Exception e)
            {
                //ignore
                return null;
            }
        }

        public static string YamlDotNet_serialize(object myobj)
        {
            var serializer = new SerializerBuilder().Build();
            var yaml = serializer.Serialize(myobj);
            return yaml;
        }

        public static object YamlDotNet_deserialize(string str)
        {
            object result = null;
            //to bypass all of the vulnerable version's type checking, we need to set up a stream
            using (var reader = new StreamReader(new MemoryStream(System.Text.Encoding.UTF8.GetBytes(str))))
            {
                var deserializer = new DeserializerBuilder().Build();
                result = deserializer.Deserialize(reader);
            }
            return result;
        }

        public static object JavaScriptSerializer_test(object myobj)
        {
            try
            {
                return JavaScriptSerializer_deserialize(JavaScriptSerializer_serialize(myobj));
            }
            catch (Exception e)
            {
                //ignore
                return null;
            }
        }

        public static string JavaScriptSerializer_serialize(object myobj)
        {
            JavaScriptSerializer jss = new JavaScriptSerializer(new SimpleTypeResolver());
            return jss.Serialize(myobj);
        }

        public static object JavaScriptSerializer_deserialize(string str)
        {
            JavaScriptSerializer jss = new JavaScriptSerializer(new SimpleTypeResolver());
            return jss.Deserialize<Object>(str);
        }

        public static object DataContractJsonSerializer_test(object gadget, string type, Type[] knownTypes)
        {
            try
            {
                return DataContractJsonSerializer_test(gadget, Type.GetType(type), knownTypes);
            }
            catch (Exception e)
            {
                //ignore
                return null;
            }
        }

        public static object DataContractJsonSerializer_test(object gadget, Type type, Type[] knownTypes)
        {
            try
            {
                return DataContractJsonSerializer_deserialize(DataContractJsonSerializer_serialize(gadget, type, knownTypes), type, knownTypes);
            }
            catch (Exception e)
            {
                //ignore
                return null;
            }
        }

        public static object DataContractJsonSerializer_deserialize(string str, string type, Type[] knownTypes)
        {
            return DataContractJsonSerializer_deserialize(str, Type.GetType(type), knownTypes);
        }

        public static object DataContractJsonSerializer_deserialize(string str, Type type, Type[] knownTypes)
        {
            DataContractJsonSerializer js = new DataContractJsonSerializer(type, new DataContractJsonSerializerSettings()
            {
                KnownTypes = knownTypes
            });
            byte[] byteArray = Encoding.UTF8.GetBytes(str);
            MemoryStream ms = new MemoryStream(byteArray);
            return js.ReadObject(ms);
        }

        public static string DataContractJsonSerializer_serialize(object gadget, string type, Type[] knownTypes)
        {
            return DataContractJsonSerializer_serialize(gadget, Type.GetType(type), knownTypes);
        }

        public static string DataContractJsonSerializer_serialize(object gadget, Type type, Type[] knownTypes)
        {
            DataContractJsonSerializer js = new DataContractJsonSerializer(type, new DataContractJsonSerializerSettings()
            {
                KnownTypes = knownTypes
            });
            MemoryStream ms = new MemoryStream();
            js.WriteObject(ms, gadget);
            return Encoding.Default.GetString(ms.ToArray());
        }

        public static object SharpSerializer_Binary_deserialize_FromByteArray(byte[] serializedData)
        {
            SharpSerializer serializer = new SharpSerializer(true); // true -> binary
            using (MemoryStream memoryStream = new MemoryStream(serializedData))
            {
                return serializer.Deserialize(memoryStream);
            }
        }

        public static object SharpSerializer_Binary_deserialize_FromBase64(string serializedDataBase64)
        {
            return SharpSerializer_Binary_deserialize_FromByteArray(Convert.FromBase64String(serializedDataBase64));
        }

        public static byte[] SharpSerializer_Binary_serialize_ToByteArray(object myobj)
        {
            return SharpSerializer_Binary_serialize_WithExclusion_ToByteArray(myobj, null);
        }

        public static string SharpSerializer_Binary_serialize_ToBase64(object myobj)
        {
            return SharpSerializer_Binary_serialize_WithExclusion_ToBase64(myobj, null);
        }

        public static byte[] SharpSerializer_Binary_serialize_WithExclusion_ToByteArray(object myobj, List<KeyValuePair<Type, List<String>>> excludedProperties)
        {
            var settings = new SharpSerializerBinarySettings();
            settings.AdvancedSettings.RootName = "r"; // to keep it short
            SharpSerializer serializer = new SharpSerializer(settings);
            using (var memoryStream = new MemoryStream())
            {
                if (excludedProperties != null)
                {
                    foreach (KeyValuePair<Type, List<String>> excKVP in excludedProperties)
                    {
                        foreach (string excPropertyName in excKVP.Value)
                        {
                            serializer.PropertyProvider.PropertiesToIgnore.Add(excKVP.Key, excPropertyName);
                        }
                    }
                }
                serializer.Serialize(myobj, memoryStream);
                return memoryStream.ToArray();
            }
        }

        public static string SharpSerializer_Binary_serialize_WithExclusion_ToBase64(object myobj, List<KeyValuePair<Type, List<String>>> excludedProperties)
        {
            return Convert.ToBase64String(SharpSerializer_Binary_serialize_WithExclusion_ToByteArray(myobj, excludedProperties));
        }

        public static object SharpSerializer_Binary_test(object myobj)
        {
            try
            {
                return SharpSerializer_Binary_deserialize_FromByteArray(SharpSerializer_Binary_serialize_ToByteArray(myobj));
            }
            catch (Exception e)
            {
                //ignore
                return null;
            }
        }

        public static object SharpSerializer_Xml_deserialize_FromByteArray(byte[] serializedData)
        {
            SharpSerializer serializer = new SharpSerializer(false); // false -> XML
            using (MemoryStream memoryStream = new MemoryStream(serializedData))
            {
                return serializer.Deserialize(memoryStream);
            }
        }

        public static object SharpSerializer_Xml_deserialize_FromString(string serializedData)
        {
            return SharpSerializer_Xml_deserialize_FromByteArray(Encoding.UTF8.GetBytes(serializedData));
        }

        public static byte[] SharpSerializer_Xml_serialize_ToByteArray(object myobj)
        {

            return SharpSerializer_Xml_serialize_WithExclusion_ToByteArray(myobj, null);
        }

        public static string SharpSerializer_Xml_serialize_ToString(object myobj)
        {
            return SharpSerializer_Xml_serialize_WithExclusion_ToString(myobj, null);
        }

        public static byte[] SharpSerializer_Xml_serialize_WithExclusion_ToByteArray(object myobj, List<KeyValuePair<Type, List<String>>> excludedProperties)
        {
            var settings = new SharpSerializerXmlSettings();
            settings.Encoding = System.Text.Encoding.ASCII;
            settings.AdvancedSettings.RootName = "r"; // to keep it short
            SharpSerializer serializer = new SharpSerializer(settings);
            using (var memoryStream = new MemoryStream())
            {
                if (excludedProperties != null)
                {
                    foreach (KeyValuePair<Type, List<String>> excKVP in excludedProperties)
                    {
                        foreach (string excPropertyName in excKVP.Value)
                        {
                            serializer.PropertyProvider.PropertiesToIgnore.Add(excKVP.Key, excPropertyName);
                        }
                    }
                }

                serializer.Serialize(myobj, memoryStream);
                return memoryStream.ToArray();
            }
        }

        public static string SharpSerializer_Xml_serialize_WithExclusion_ToString(object myobj, List<KeyValuePair<Type, List<String>>> excludedProperties)
        {
            return Encoding.UTF8.GetString(SharpSerializer_Xml_serialize_WithExclusion_ToByteArray(myobj, excludedProperties));
        }

        public static object SharpSerializer_Xml_test(object myobj)
        {
            try
            {
                return SharpSerializer_Xml_deserialize_FromByteArray(SharpSerializer_Xml_serialize_ToByteArray(myobj));
            }
            catch (Exception e)
            {
                //ignore
                return null;
            }
        }

        private static string MessagePackTypeless_serialize_ToBase64(object myobj)
        {
            MessagePackSerializerOptions options = TypelessContractlessStandardResolver.Options;
            var serialized = MessagePackSerializer.Serialize(myobj, options);
            return Convert.ToBase64String(serialized);
        }

        private static string MessagePackTypeless_Lz4_serialize_ToBase64(object myobj)
        {
            MessagePackSerializerOptions options = TypelessContractlessStandardResolver.Options.WithCompression(MessagePackCompression.Lz4BlockArray);
            var serialized = MessagePackSerializer.Serialize(myobj, options);
            return Convert.ToBase64String(serialized);
        }

        public static object MessagePackTypeless_test(object myobj)
        {
            try
            {
                MessagePackSerializerOptions options = TypelessContractlessStandardResolver.Options;
                var serialized = MessagePackSerializer.Serialize(myobj, options);
                return MessagePackSerializer.Deserialize<object>(serialized, options);
            }
            catch (Exception e)
            {
                //ignore
                return null;
            }
        }

        public static object MessagePackTypelessLz4_test(object myobj)
        {
            try
            {
                MessagePackSerializerOptions options = TypelessContractlessStandardResolver.Options.WithCompression(MessagePackCompression.Lz4BlockArray);
                var serialized = MessagePackSerializer.Serialize(myobj, options);
                return MessagePackSerializer.Deserialize<object>(serialized, options);
            }
            catch (Exception e)
            {
                //ignore
                return null;
            }
        }
    }
}