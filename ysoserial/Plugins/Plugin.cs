using System;
using NDesk.Options;

namespace ysoserial_frmv2.Plugins
{
    interface Plugin
    {
        string Name();
        string Description();
        OptionSet Options();
        object Run(String[] args);
    }
}
