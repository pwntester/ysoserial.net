using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ysoserial.Generators
{
    class ObjectDataProviderGenerator : GenericGenerator
    {
        public override string Description()
        {
            return "ObjectDataProvider Gadget by Oleksandr Mirosh and Alvaro Munoz";
        }

        public override List<string> SupportedFormatters()
        {
            return new List<string> { "Json.Net", "FastJson", "JavaScriptSerializer" };
        }

        public override string Name()
        {
            return "ObjectDataProvider";
        }

        public override object Generate(string cmd, string formatter, Boolean test)
        {
            return Serialize(cmd, formatter, test);
        }
    }
}
