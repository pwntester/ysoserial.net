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

        public abstract object Generate(string cmd, string formatter, Boolean test, Boolean minify, Boolean useSimpleType);

        public abstract string Credit();

        public abstract string Name();

        public abstract bool isDerived();

        public abstract List<string> SupportedFormatters();

        public Boolean IsSupported(string formatter)
        {
            var formatters = SupportedFormatters();
            var lowercased = formatters.Select(x => x.Split(new string[] { " " }, StringSplitOptions.None)[0].ToLower()).ToList();
            if (lowercased.Contains(formatter.ToLower())) return true;
            else return false;
        }

        public object Serialize(object cmdobj, string formatter, Boolean test, Boolean minify)
        {
            return Serialize(cmdobj, formatter, test, minify, false);
        }

        public object Serialize(object cmdobj, string formatter, Boolean test, Boolean minify, Boolean useSimpleType)
        {
            // Disable ActivitySurrogate type protections during generation
            ConfigurationManager.AppSettings.Set("microsoft:WorkflowComponentModel:DisableActivitySurrogateSelectorTypeCheck", "true");

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

                if (minify)
                {
                    stream.Position = 0;
                    if (useSimpleType)
                    {
                        stream = XMLMinifier.Minify(stream, new String[] { "Microsoft.PowerShell.Editor" }, null, FormatterType.SoapFormatter, true);
                    }
                    else
                    {
                        stream = XMLMinifier.Minify(stream, null, null, FormatterType.SoapFormatter, true);
                    }
                }

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

                if (minify)
                {
                    stream.Position = 0;
                    if (useSimpleType)
                    {
                        stream = XMLMinifier.Minify(stream, new string[] { "mscorlib", "Microsoft.PowerShell.Editor" }, null, FormatterType.NetDataContractXML, true);
                    }
                    else
                    {
                        stream = XMLMinifier.Minify(stream, null, null, FormatterType.NetDataContractXML, true);
                    }
                }

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
            else
            {
                throw new Exception("Formatter not supported");
            }
        }
    }
}
