using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Runtime.Serialization.Formatters.Soap;
using System.Web.UI;
using System.Linq;
using System.Configuration;
using ysoserial.Helpers;

namespace ysoserial.Generators
{
    abstract class GenericGenerator : Generator
    {
        public abstract string Description();
        public abstract object Generate(string formatter, InputArgs inputArgs);
        public abstract string Finders();
        public abstract string Name();
        public abstract List<string> SupportedFormatters();

        public object GenerateWithNoTest(string formatter, InputArgs inputArgs)
        {
            InputArgs tempInputArgs = inputArgs.DeepCopy();
            tempInputArgs.Test = false;
            return Generate(formatter, tempInputArgs);
        }

        public virtual List<string> Labels()
        {
            return new List<string> {""};
        }

        public virtual string Contributors()
        {
            return "";
        }

        public string Credit()
        {
            if (String.IsNullOrEmpty(Contributors()) || Finders().ToLower().Equals(Contributors().ToLower()))
            {
                return "[Finders: " + Finders() + "]";
            }
            else
            {
                return "[Finders: " + Finders() + "] [Contributors: " + Contributors() + "]";
            }
            
        }

        public Boolean IsSupported(string formatter)
        {
            var formatters = SupportedFormatters();
            var lowercased = formatters.Select(x => x.Split(new string[] { " " }, StringSplitOptions.None)[0].ToLower()).ToList();
            if (lowercased.Contains(formatter.ToLower())) return true;
            else return false;
        }

        public object Serialize(object payloadObj, string formatter, InputArgs inputArgs)
        {
            // Disable ActivitySurrogate type protections during generation
            ConfigurationManager.AppSettings.Set("microsoft:WorkflowComponentModel:DisableActivitySurrogateSelectorTypeCheck", "true");

            MemoryStream stream = new MemoryStream();
          
            if (formatter.ToLower().Equals("binaryformatter"))
            {
                BinaryFormatter fmt = new BinaryFormatter();
                fmt.Serialize(stream, payloadObj);
                if (inputArgs.Test)
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
                osf.Serialize(stream, payloadObj);
                if (inputArgs.Test)
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
                sf.Serialize(stream, payloadObj);

                if (inputArgs.Minify)
                {
                    stream.Position = 0;
                    if (inputArgs.UseSimpleType)
                    {
                        stream = XMLMinifier.Minify(stream, new String[] { "Microsoft.PowerShell.Editor" }, null, FormatterType.SoapFormatter, true);
                    }
                    else
                    {
                        stream = XMLMinifier.Minify(stream, null, null, FormatterType.SoapFormatter, true);
                    }
                }

                if (inputArgs.Test)
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
                ndcs.Serialize(stream, payloadObj);

                if (inputArgs.Minify)
                {
                    stream.Position = 0;
                    if (inputArgs.UseSimpleType)
                    {
                        stream = XMLMinifier.Minify(stream, new string[] { "mscorlib", "Microsoft.PowerShell.Editor" }, null, FormatterType.NetDataContractXML, true);
                    }
                    else
                    {
                        stream = XMLMinifier.Minify(stream, null, null, FormatterType.NetDataContractXML, true);
                    }
                }

                if (inputArgs.Test)
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
                lf.Serialize(stream, payloadObj);
                if (inputArgs.Test)
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
            else
            {
                throw new Exception("Formatter not supported");
            }
        }

    }
}
