using System;
using System.IO;
using System.Text;

namespace ysoserial.Helpers.ModifiedVulnerableBinaryFormatters
{
    public class SimpleMinifiedObjectLosFormatter
    {
        public static MemoryStream Serialize(Object inputObj)
        {
            ModifiedVulnerableBinaryFormatters.BinaryFormatter fmtLocal = new ModifiedVulnerableBinaryFormatters.BinaryFormatter();

            MemoryStream ms = new MemoryStream();
            fmtLocal.Serialize(ms, inputObj);

            return BFStreamToLosFormatterStream(ms);
        }

        public static MemoryStream BFStreamToLosFormatterStream(MemoryStream serializedStream)
        {
            return new MemoryStream(BFStreamToLosFormatterStream(serializedStream.ToArray()));
        }

        public static byte[] BFStreamToLosFormatterStream(byte[] serializedBytes)
        {
            byte[] inputSize7Bit = SimpleBinaryFormatterParser.Calculate7BitEncodedInt(serializedBytes.Length);
            byte[] newSerializedData = new byte[3 + inputSize7Bit.Length + serializedBytes.Length];
            serializedBytes.CopyTo(newSerializedData, 3 + inputSize7Bit.Length);
            newSerializedData[0] = 0xff; // header
            newSerializedData[1] = 0x01; // 1 object
            newSerializedData[2] = 0x32; // type object
            // length here
            inputSize7Bit.CopyTo(newSerializedData, 3);
            
            return Encoding.UTF8.GetBytes(Convert.ToBase64String(newSerializedData));
        }

        
    }
}
