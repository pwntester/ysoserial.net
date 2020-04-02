using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ysoserial.Helpers.ModifiedVulnerableBinaryFormatters
{
    public class SimpleMinifiedObjectLosFormatter
    {
        public static MemoryStream Serialize(Object inputObj)
        {
            ModifiedVulnerableBinaryFormatters.BinaryFormatter fmtLocal = new ModifiedVulnerableBinaryFormatters.BinaryFormatter();

            MemoryStream ms = new MemoryStream();
            fmtLocal.Serialize(ms, inputObj);

            return PrepareWithSerialized(ms);
        }

        public static MemoryStream PrepareWithSerialized(MemoryStream serializedStream)
        {   
            return new MemoryStream(PrepareWithSerialized(serializedStream.ToArray()));
        }

        public static byte[] PrepareWithSerialized(byte[] serializedBytes)
        {
            byte[] inputSize7Bit = Calculate7BitEncodedInt(serializedBytes.Length);
            byte[] newSerializedData = new byte[3 + inputSize7Bit.Length + serializedBytes.Length];
            serializedBytes.CopyTo(newSerializedData, 3 + inputSize7Bit.Length);
            newSerializedData[0] = 0xff; // header
            newSerializedData[1] = 0x01; // 1 object
            newSerializedData[2] = 0x32; // type object
            // length here
            inputSize7Bit.CopyTo(newSerializedData, 3);
            
            return Encoding.UTF8.GetBytes(Convert.ToBase64String(newSerializedData));
        }

        public static byte[] Calculate7BitEncodedInt(int value)
        {
            // it cannot be more than 5 bytes according to [MS-NRBF]
            byte[] output = new byte[1];
            // Similar to Write7BitEncodedInt from System.IO.BinaryWriter
            uint v = (uint)value; 
            int counter = 0;

            while (v >= 0x80)
            {
                if (counter > 1)
                    Array.Resize(ref output, counter+1);

                output[counter] = ((byte)(v | 0x80));
                v >>= 7;
                counter++;
            }

            if (counter > 0)
                Array.Resize(ref output, counter+1);

            output[counter] = ((byte)v);

            return output;
        }
    }
}
