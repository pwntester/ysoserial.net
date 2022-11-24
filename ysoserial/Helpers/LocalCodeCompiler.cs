using System;
using System.CodeDom.Compiler;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Controls.Primitives;

namespace ysoserial.Helpers
{
    public static class LocalCodeCompiler
    {

        public static byte[] CompileToAsmBytes(string fileChain)
        {
            return CompileToAsmBytes(fileChain, "", "");
        }

        public static byte[] CompileToAsmBytes(string fileChain, string compilerLanguage, string compilerOptions)
        {
            byte[] assemblyBytes = null;
            try
            {
                if (string.IsNullOrEmpty(compilerOptions))
                {
                    compilerOptions = "-t:library -o+ -platform:anycpu";
                }

                if (string.IsNullOrEmpty(compilerLanguage))
                {
                    compilerLanguage = "CSharp";
                }

                string[] files = fileChain.Split(new[] { ';' }).Select(s => s.Trim()).ToArray();
                CodeDomProvider codeDomProvider = CodeDomProvider.CreateProvider(compilerLanguage);
                CompilerParameters compilerParameters = new CompilerParameters();
                compilerParameters.CompilerOptions = compilerOptions;
                compilerParameters.ReferencedAssemblies.AddRange(files.Skip(1).ToArray());
                CompilerResults compilerResults = codeDomProvider.CompileAssemblyFromFile(compilerParameters, files[0]);
                if (compilerResults.Errors.Count > 0)
                {
                    foreach (CompilerError error in compilerResults.Errors)
                    {
                        Console.Error.WriteLine(error.ErrorText);
                    }
                    Environment.Exit(-1);
                }
                assemblyBytes = File.ReadAllBytes(compilerResults.PathToAssembly);
                File.Delete(compilerResults.PathToAssembly);
            }
            catch(Exception e)
            {
                Console.Error.WriteLine(e.Message);
                Environment.Exit(-1);
            }
            
            return assemblyBytes;
        }
    }
}
