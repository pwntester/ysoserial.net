using System;

namespace TestConsoleApp_YSONET
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("This is just for code execution testing.");
            Console.WriteLine("Args: ");
            Console.WriteLine(string.Join(",", args));
            Console.ReadLine();
        }
    }
}
