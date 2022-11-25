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
using NDesk.Options;
using System.Reflection;

namespace ysoserial.Generators
{
    public abstract class GenericGenerator : IGenerator
    {
        public SerializationBinder serializationBinder = null;
        public abstract object Generate(string formatter, InputArgs inputArgs);
        public abstract string Finders();
        public abstract string Name();
        public abstract List<string> SupportedFormatters();
        
        // This is used when we want a gadget to support incoming from another gadget
        public virtual string SupportedBridgedFormatter()
        {
            return Formatters.None;
        }
        public object BridgedPayload { get; set ;}

        public virtual string AdditionalInfo()
        {
            // This is when we have nothing more to add to keep the help section cleaner
            return "";
        }

        public virtual void Init(InputArgs inputArgs)
        {
            // Overridable to provide more flexibility for rare cases
            OptionSet options = Options();
            if (options != null)
            {
                InputArgs tempInputArgs = inputArgs.DeepCopy();

                if (tempInputArgs.ExtraInternalArguments.Count > 0)
                {
                    // This means it is an internal call from other gadgets or plugins so current ExtraArguments becomes irrelevant and ExtraInternalArguments are important
                    tempInputArgs.ExtraArguments = tempInputArgs.ExtraInternalArguments;
                    tempInputArgs.ExtraInternalArguments = new List<string>(); // Clearing the list to prevent double use just in case!
                }

                try
                {
                    List<String> extraArguments = Options().Parse(tempInputArgs.ExtraArguments);
                }
                catch (OptionException e)
                {
                    Console.Write("ysoserial: ");
                    Console.WriteLine(e.Message);
                    Console.WriteLine("Extra options for " + Name() + " are as follows:");
                    options.WriteOptionDescriptions(Console.Out);
                    System.Environment.Exit(-1);
                }
            }
        }

        public virtual OptionSet Options()
        {
            return null;
        }

        public object GenerateWithInit(string formatter, InputArgs inputArgs)
        {
            Init(inputArgs);
            return Generate(formatter, inputArgs);
        }

        public object GenerateWithNoTest(string formatter, InputArgs inputArgs)
        {
            InputArgs tempInputArgs = inputArgs.DeepCopy();
            tempInputArgs.Test = false;
            return GenerateWithInit(formatter, tempInputArgs);
        }

        public object SerializeWithInit(object payloadObj, string formatter, InputArgs inputArgs)
        {
            Init(inputArgs);
            return Serialize(payloadObj, formatter, inputArgs);
        }

        public object SerializeWithNoTest(object payloadObj, string formatter, InputArgs inputArgs)
        {
            InputArgs tempInputArgs = inputArgs.DeepCopy();
            tempInputArgs.Test = false;
            return SerializeWithInit(payloadObj, formatter, tempInputArgs);
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
            MemoryStream stream = new MemoryStream();
          
            if (formatter.ToLower().Equals("binaryformatter"))
            {
                BinaryFormatter fmt = new BinaryFormatter();

                if (inputArgs.Minify)
                {
                    ysoserial.Helpers.ModifiedVulnerableBinaryFormatters.BinaryFormatter fmtLocal = new ysoserial.Helpers.ModifiedVulnerableBinaryFormatters.BinaryFormatter();
                    fmtLocal.Serialize(stream, payloadObj);
                }
                else
                {
                    fmt.Serialize(stream, payloadObj);
                }
                
                
                if (inputArgs.Test)
                {
                    try
                    {
                        stream.Position = 0;
                        if (serializationBinder != null)
                            fmt.Binder = serializationBinder;
                        fmt.Deserialize(stream);
                    } 
                    catch(Exception err){
                        Debugging.ShowErrors(inputArgs, err);
                    }
                }
                return stream.ToArray();
            }
            /*
             * We don't actually need to use ObjectStateFormatter in ysoserial.net because it is the same as LosFormatter without MAC/keys
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
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                    }
                }
                return stream.ToArray();
            }
            */
            else if (formatter.ToLower().Equals("soapformatter"))
            {
                SoapFormatter sf = new SoapFormatter();
                sf.Serialize(stream, payloadObj);

                if (inputArgs.Minify)
                {
                    stream.Position = 0;
                    if (inputArgs.UseSimpleType)
                    {
                        stream = XmlHelper.Minify(stream, new String[] { "Microsoft.PowerShell.Editor" }, null, FormatterType.SoapFormatter, true);
                    }
                    else
                    {
                        stream = XmlHelper.Minify(stream, null, null, FormatterType.SoapFormatter, true);
                    }
                }

                if (inputArgs.Test)
                {
                    try
                    {
                        stream.Position = 0;
                        if (serializationBinder != null)
                            sf.Binder = serializationBinder;
                        sf.Deserialize(stream);
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
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
                        stream = XmlHelper.Minify(stream, new string[] { "mscorlib", "Microsoft.PowerShell.Editor" }, new string[] { @"\<Signature2[^\/]+<\/Signature2\>" }, FormatterType.NetDataContractXML, true);
                    }
                    else
                    {
                        stream = XmlHelper.Minify(stream, null, null, FormatterType.NetDataContractXML, true);
                    }
                }

                if (inputArgs.Test)
                {
                    try
                    {
                        stream.Position = 0;
                        if (serializationBinder != null)
                            ndcs.Binder = serializationBinder;
                        ndcs.Deserialize(stream);
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                    }
                }
                return stream.ToArray();
            }
            else if (formatter.ToLower().Equals("losformatter"))
            {
                LosFormatter lf = new LosFormatter();

                if (inputArgs.Minify)
                {
                    stream = Helpers.ModifiedVulnerableBinaryFormatters.SimpleMinifiedObjectLosFormatter.Serialize(payloadObj);
                }
                else
                {
                    lf.Serialize(stream, payloadObj);
                }
                
                if (inputArgs.Test)
                {
                    try
                    {
                        stream.Position = 0;
                        lf.Deserialize(stream);
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
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
