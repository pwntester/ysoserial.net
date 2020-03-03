using System;
using System.IO;
using static ysoserial.Helpers.CommandArgSplitter;

namespace ysoserial.Helpers
{
    class InputArgs
    {
        private string _cmdFullString;
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
                if (File.Exists(_cmdFullString))
                {
                    Console.Error.WriteLine("Reading command from file " + _cmdFullString + " ...");
                    _cmdFromFile = File.ReadAllText(_cmdFullString);
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
            return newInputArgs;
        }

    }
}
