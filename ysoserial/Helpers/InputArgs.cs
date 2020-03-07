using System;
using System.Collections.Generic;
using System.IO;
using static ysoserial.Helpers.CommandArgSplitter;

namespace ysoserial.Helpers
{
    public class InputArgs
    {
        private string _cmdFileName;
        private string _cmdArguments;
        private string _cmdFromFile;
        private string _cmdRawNoEncoding;
        private bool _hasArguments;
        private CommandType _cmdType = CommandType.None;

        private bool _test = false;
        private bool _minify = false;
        private bool _useSimpleType = false;
        private bool _isRawCmd = false;
        private bool _isDebugMode = false;
        private List<String> _extraArguments = new List<string>();
        private List<String> _extraInternalArguments = new List<string>(); // This is used as ExtraArguments when calling GenerateWithNoTest to stop passing unwanted extra options 

        public string CmdFullString
        {
            get
            {
                string tempFullCmd;
                
                if (IsRawCmd)
                {
                    tempFullCmd = this.Cmd;
                }
                else
                {
                    tempFullCmd = "cmd /c " + this.Cmd;
                }

                bool hasArgs;
                string[] splittedCmd = CommandArgSplitter.SplitCommand(tempFullCmd, this.CmdType, out hasArgs);

                this.CmdFileName = splittedCmd[0];

                this.HasArguments = hasArgs;

                if (hasArgs)
                {
                    this.CmdArguments = splittedCmd[1];
                }

                tempFullCmd = String.Join(" ", splittedCmd);
                return tempFullCmd;

            }

        }

        public string CmdFileName
        {
            get
            {
                if (!CmdFullString.Equals(""))
                {
                    return _cmdFileName;
                }
                else
                {
                    return "";
                }
                
            }

            private set
            {
                _cmdFileName = value;
            }
        }

        public string CmdArguments
        {
            get
            {
                if (!CmdFullString.Equals(""))
                {
                    return _cmdArguments;
                }
                else
                {
                    return "";
                }
                
            }

            private set
            {
                _cmdArguments = value;
            }
        }

        public string Cmd
        {
            get
            {
                return _cmdRawNoEncoding;
            }

            set
            {
                _cmdRawNoEncoding = value;
            }
        }

        // this is when cmd is used to read from a file
        // return null if cmd is not a file
        public string CmdFromFile
        {
            get
            {
                if (File.Exists(Cmd))
                {
                    Console.Error.WriteLine("Reading command from file " + Cmd + " ...");
                    _cmdFromFile = File.ReadAllText(Cmd);
                }
                else
                {
                    _cmdFromFile = null;
                }

                return _cmdFromFile;
            }

            set
            {
                _cmdFromFile = value;
            }
        }

        public bool Test
        {
            get
            {
                return _test;
            }

            set
            {
                _test = value;
            }
        }

        public bool Minify
        {
            get
            {
                return _minify;
            }

            set
            {
                _minify = value;
            }
        }

        public bool UseSimpleType
        {
            get
            {
                return _useSimpleType;
            }

            set
            {
                _useSimpleType = value;
            }
        }

        public bool IsRawCmd
        {
            get
            {
                return _isRawCmd;
            }

            set
            {
                _isRawCmd = value;
            }
        }

        public CommandType CmdType
        {
            get
            {
                return _cmdType;
            }

            set
            {
                _cmdType = value;
            }
        }

        public bool HasArguments
        {
            get
            {
                if (!CmdFullString.Equals(""))
                {
                    return _hasArguments;
                }
                else
                {
                    return false;
                }
                    
            }

            private set
            {
                _hasArguments = value;
            }
        }

        public List<string> ExtraArguments
        {
            get
            {
                return _extraArguments;
            }

            set
            {
                _extraArguments = value;
            }
        }

        public bool IsDebugMode
        {
            get
            {
                return _isDebugMode;
            }

            set
            {
                _isDebugMode = value;
            }
        }

        public List<string> ExtraInternalArguments
        {
            get
            {
                return _extraInternalArguments;
            }

            set
            {
                _extraInternalArguments = value;
            }
        }

        public InputArgs ShallowCopy()
        {
            return (InputArgs)this.MemberwiseClone();
        }

        public InputArgs DeepCopy()
        {
            InputArgs newInputArgs = new InputArgs();
            newInputArgs.Cmd = this._cmdRawNoEncoding;
            newInputArgs.IsRawCmd = this._isRawCmd;
            newInputArgs.Test = this._test;
            newInputArgs.Minify = this._minify;
            newInputArgs.UseSimpleType = this._useSimpleType;
            newInputArgs.ExtraArguments = this.ExtraArguments;
            newInputArgs.ExtraInternalArguments = this.ExtraInternalArguments;
            newInputArgs.IsDebugMode = this.IsDebugMode;
            return newInputArgs;
        }

    }
}
