using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ysoserial.Helpers
{
    public enum FormatterType : ushort
    {
        None = 0,
        BinaryFormatter = 1,
        SoapFormatter = 2,
        LosFormatter = 3,
        ObjectStateFormatter = 4,
        DataContractXML = 5,
        NetDataContractXML = 6,
        XMLSerializer = 7,
        JavascriptSerializer = 8,
    }
}
