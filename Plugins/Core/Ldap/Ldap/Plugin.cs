/*
	Copyright (c) 2014, pGina Team
	All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:
		* Redistributions of source code must retain the above copyright
		  notice, this list of conditions and the following disclaimer.
		* Redistributions in binary form must reproduce the above copyright
		  notice, this list of conditions and the following disclaimer in the
		  documentation and/or other materials provided with the distribution.
		* Neither the name of the pGina Team nor the names of its contributors 
		  may be used to endorse or promote products derived from this software without 
		  specific prior written permission.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
	ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
	WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
	DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY
	DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
	(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
	LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
	ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
	SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.DirectoryServices.Protocols;

using log4net;

using pGina.Shared.Interfaces;
using pGina.Shared.Types;
using WinSCP;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace pGina.Plugin.Ldap
{
    public class LdapPlugin : IStatefulPlugin, IPluginAuthentication, IPluginAuthorization, IPluginAuthenticationGateway, IPluginConfiguration, IPluginChangePassword
    {
        public static readonly Guid LdapUuid = new Guid("{0F52390B-C781-43AA-BD62-553C77FA4CF7}");
        private ILog m_logger = LogManager.GetLogger("LdapPlugin");

        private static string getPathToLoginScript(string user)
        {
            return @"D:\loginScript.bat";
        }

        public LdapPlugin()
        {
            using(Process me = Process.GetCurrentProcess())
            {
                m_logger.DebugFormat("LDAP Plugin initialized on {0} in PID: {1} Session: {2}", Environment.MachineName, me.Id, me.SessionId);
            }
        }

        public string Name
        {
            get { return "LDAP"; }
        }

        public string Description
        {
            get { return "Uses a LDAP server as a data source for authentication and/or group authorization."; }
        }

        public string Version
        {
            get 
            { 
                return System.Reflection.Assembly.GetExecutingAssembly().GetName().Version.ToString(); 
            }
        }

        public Guid Uuid
        {
            get { return LdapUuid; }
        }
        
        public BooleanResult AuthenticateUser(Shared.Types.SessionProperties properties)
        {
            // Get the LdapServer object from the session properties (created in BeginChain)
            LdapServer server = properties.GetTrackedSingle<LdapServer>();
            if (server == null)
                return new BooleanResult() { Success = false, Message = "Internal error: LdapServer object not available" };

            try
            {
                m_logger.DebugFormat("AuthenticateUser({0})", properties.Id.ToString());
                Shared.Types.UserInformation userInfo = properties.GetTrackedSingle<Shared.Types.UserInformation>();
                m_logger.DebugFormat("Received username: {0}", userInfo.Username);

                // Authenticate the login
                m_logger.DebugFormat("Attempting authentication for {0}", userInfo.Username);

                // Se o login foi realizado com sucesso, vamos mapear o disco da rede.
                BooleanResult result = server.Authenticate(userInfo.Username, userInfo.Password);
                return result;
            }
            catch (Exception e)
            {
                if (e is LdapException)
                {
                    LdapException ldapEx = (e as LdapException);
                    
                    if (ldapEx.ErrorCode == 81)
                    {
                        // Server can't be contacted, set server object to null
                        m_logger.ErrorFormat("Server unavailable: {0}, {1}", ldapEx.ServerErrorMessage, e.Message);
                        server.Close();
                        properties.AddTrackedSingle<LdapServer>(null);
                        return new BooleanResult { Success = false, Message = "Failed to contact LDAP server." };
                    }
                }

                // This is an unexpected error, so set LdapServer object to null, because
                // subsequent stages shouldn't use it, and this indicates to later stages
                // that this stage failed unexpectedly.
                server.Close();
                properties.AddTrackedSingle<LdapServer>(null);
                m_logger.ErrorFormat("Exception in LDAP authentication: {0}", e);
                throw;  // Allow pGina service to catch and handle exception
            }
        }        

        public void Configure()
        {
            Configuration conf = new Configuration();
            conf.ShowDialog();
        }

        public void Starting() { }
        public void Stopping() { }

        public void BeginChain(SessionProperties props)
        {
            m_logger.Debug("BeginChain");
            try
            {
                LdapServer serv = new LdapServer();
                props.AddTrackedSingle<LdapServer>(serv);
            }
            catch (Exception e)
            {
                m_logger.ErrorFormat("Failed to create LdapServer: {0}", e);
                props.AddTrackedSingle<LdapServer>(null);
            }
        }

        public void EndChain(SessionProperties props)
        {
            m_logger.Debug("EndChain");
            LdapServer serv = props.GetTrackedSingle<LdapServer>();
            if (serv != null) serv.Close();
        }

        public BooleanResult AuthorizeUser(SessionProperties properties)
        {
            m_logger.Debug("LDAP Plugin Authorization");

            // Do we need to do authorization?
            if (DoesAuthzApply(properties))
            {
                bool requireAuth = Settings.Store.AuthzRequireAuth;

                // Get the authz rules from registry
                List<GroupAuthzRule> rules = GroupRuleLoader.GetAuthzRules();
                if (rules.Count == 0)
                {
                    throw new Exception("No authorizaition rules found.");
                }

                // Get the LDAP server object
                LdapServer serv = properties.GetTrackedSingle<LdapServer>();

                // If LDAP server object is not found, then something went wrong in authentication.
                // We allow or deny based on setting
                if (serv == null)
                {
                    m_logger.ErrorFormat("AuthorizeUser: Internal error, LdapServer object not available.");

                    // LdapServer is not available, allow or deny based on settings.
                    return new BooleanResult()
                    {
                        Success = Settings.Store.AuthzAllowOnError,
                        Message = "LDAP server unavailable."
                    };
                }

                // If we require authentication, and we failed to auth this user, then we
                // fail authorization.  Note that we do this AFTER checking the LDAP server object
                // because we may want to succeed if the authentication failed due to server
                // being unavailable.
                if (requireAuth && !WeAuthedThisUser(properties))
                {
                    m_logger.InfoFormat("Deny because LDAP auth failed, and configured to require LDAP auth.");
                    return new BooleanResult()
                    {
                        Success = false,
                        Message = "Deny because LDAP authentication failed, or did not execute."
                    };
                }

                // Apply the authorization rules
                try
                {
                    UserInformation userInfo = properties.GetTrackedSingle<UserInformation>();
                    string user = userInfo.Username;

                    // Bind for searching if we have rules to process.  If there's only one, it's the
                    // default rule which doesn't require searching the LDAP tree.
                    if (rules.Count > 1)
                    {
                        this.BindForAuthzOrGatewaySearch(serv);
                    }

                    foreach (GroupAuthzRule rule in rules)
                    {
                        bool inGroup = false;

                        // Don't need to check membership if the condition is "always."  This is the
                        // case for the default rule only. which is the last rule in the list.
                        if (rule.RuleCondition != GroupRule.Condition.ALWAYS)
                        {
                            inGroup = serv.MemberOfGroup(user, rule.Group);
                            m_logger.DebugFormat("User {0} {1} member of group {2}", user, inGroup ? "is" : "is not",
                                rule.Group);
                        }

                        if (rule.RuleMatch(inGroup))
                        {
                            if (rule.AllowOnMatch)
                                return new BooleanResult()
                                {
                                    Success = true,
                                    Message = string.Format("Allow via rule: \"{0}\"", rule.ToString())
                                };
                            else
                                return new BooleanResult()
                                {
                                    Success = false,
                                    Message = string.Format("Deny via rule: \"{0}\"", rule.ToString())
                                };
                        }
                    }

                    // We should never get this far because the last rule in the list should always be a match,
                    // but if for some reason we do, return success.
                    return new BooleanResult() { Success = true, Message = "" };
                }
                catch (Exception e)
                {
                    if (e is LdapException)
                    {
                        LdapException ldapEx = (e as LdapException);

                        if (ldapEx.ErrorCode == 81)
                        {
                            // Server can't be contacted, set server object to null
                            m_logger.ErrorFormat("Server unavailable: {0}, {1}", ldapEx.ServerErrorMessage, e.Message);
                            serv.Close();
                            properties.AddTrackedSingle<LdapServer>(null);
                            return new BooleanResult
                            {
                                Success = Settings.Store.AuthzAllowOnError,
                                Message = "Failed to contact LDAP server."
                            };
                        }
                        else if (ldapEx.ErrorCode == 49)
                        {
                            // This is invalid credentials, return false, but server object should remain connected
                            m_logger.ErrorFormat("LDAP bind failed: invalid credentials.");
                            return new BooleanResult
                            {
                                Success = false,
                                Message = "Authorization via LDAP failed. Invalid credentials."
                            };
                        }
                    }

                    // Unexpected error, let the PluginDriver catch
                    m_logger.ErrorFormat("Error during authorization: {0}", e);
                    throw;
                }
            }
            else
            {
                // We elect to not do any authorization, let the user pass for us
                return new BooleanResult() { Success = true };
            }
        }

        private bool DoesAuthzApply(SessionProperties properties)
        {
            // Do we authorize all users?
            bool authzAllUsers = Settings.Store.AuthzApplyToAllUsers;
            if (authzAllUsers) return true;

            // Did we auth this user?
            return WeAuthedThisUser(properties);
        }

        static void ExecuteCommand(string command)
        {
            var processInfo = new ProcessStartInfo("cmd.exe", "/c " + command);
            processInfo.CreateNoWindow = true;
            processInfo.UseShellExecute = false;

            var process = Process.Start(processInfo);

            process.WaitForExit();
            process.Close();
        }

        // Adds an ACL entry on the specified file for the specified account.
        public static void AddFileSecurity(string fileName, string account,
            FileSystemRights rights, AccessControlType controlType)
        {


            // Get a FileSecurity object that represents the
            // current security settings.
            FileSecurity fSecurity = File.GetAccessControl(fileName);

            // Add the FileSystemAccessRule to the security settings.
            fSecurity.AddAccessRule(new FileSystemAccessRule(account,
                rights, controlType));

            // Set the new access settings.
            File.SetAccessControl(fileName, fSecurity);

        }


        private void LoginScipt(string paramScriptPath, List<string> groups, UserInformation userInfo, LdapServer serv, Session session)
        {
            int len_groups = groups.Count;
            int i = 0;
            do
            {
                string script_path = paramScriptPath;
                if (!script_path.Contains("%g"))
                    len_groups = 0;  // ignore groups 

                script_path = script_path.Replace("%u", userInfo.Username.Trim());

                // Verifica se o usuário está em um grupo.
                
                if (len_groups > 0 && i < len_groups)
                {
                    if (serv.MemberOfGroup(userInfo.Username, groups[i].Trim()))
                    {
                        script_path = script_path.Replace("%g", groups[i].Trim());
                        m_logger.DebugFormat("Replacing %g to |{0}| ", groups[i].Trim());
                    }
                    else
                    {
                        i++;
                        continue;
                    }
                }

                TransferOperationResult transferResult;
                if (!session.FileExists(script_path))
                {
                    i++;
                    if (i >= len_groups)
                        return;
                    m_logger.DebugFormat("File {0} doesn't exist!", script_path);
                    continue;
                }

                m_logger.DebugFormat("Downloading file {0} ", script_path);
                transferResult = session.GetFiles(script_path, @"D:\", false, null);

                // Throw on any error
                transferResult.Check();

                // Print results
                foreach (TransferEventArgs transfer in transferResult.Transfers)
                {
                    m_logger.DebugFormat("Downalod of {0} succeeded", transfer.FileName);
                }
                int index = script_path.LastIndexOf(@"\");
                if (index < 0)
                    index = script_path.LastIndexOf("/");
                if (index < 0)
                    index = -1;
                script_path = script_path.Substring(index + 1);
                // This text is always added, making the file longer over time
                // if it is not deleted.
                m_logger.DebugFormat("Saving script {0}", script_path);
                using (StreamWriter sw = new StreamWriter(getPathToLoginScript(userInfo.Username), true))
                {
                    System.IO.StreamReader file = new System.IO.StreamReader(@"D:\" + script_path);
                    string line = "";
                    while ((line = file.ReadLine()) != null)
                    {
                        sw.WriteLine(line);
                    }
                    file.Close();
                }
                ExecuteCommand(@"DEL D:\" + script_path);
                i++;
            } while (i < len_groups);

        }

        public BooleanResult AuthenticatedUserGateway(SessionProperties properties)
        {
            m_logger.Debug("LDAP Plugin Gateway");
            List<string> addedGroups = new List<string>();

            LdapServer serv = properties.GetTrackedSingle<LdapServer>();

            // If the server is unavailable, we go ahead and succeed anyway.
            if (serv == null)
            {
                m_logger.ErrorFormat("AuthenticatedUserGateway: Internal error, LdapServer object not available.");
                return new BooleanResult() 
                { 
                    Success = true, 
                    Message = "LDAP server not available" 
                };
            }

            try
            {
                UserInformation userInfo = properties.GetTrackedSingle<UserInformation>();
                string user = userInfo.Username;

                List<GroupGatewayRule> rules = GroupRuleLoader.GetGatewayRules();
                bool boundToServ = false;
                foreach (GroupGatewayRule rule in rules)
                {
                    bool inGroup = false;

                    // Don't need to check for group membership if the rule is to be always applied.
                    if (rule.RuleCondition != GroupRule.Condition.ALWAYS)
                    {
                        // If we haven't bound to server yet, do so.
                        if (!boundToServ)
                        {
                            this.BindForAuthzOrGatewaySearch(serv);
                            boundToServ = true;
                        }

                        inGroup = serv.MemberOfGroup(user, rule.Group);
                        m_logger.DebugFormat("User {0} {1} member of group {2}", user, inGroup ? "is" : "is not",
                            rule.Group);
                    }

                    if (rule.RuleMatch(inGroup))
                    {
                        m_logger.InfoFormat("Adding user {0} to local group {1}, due to rule \"{2}\"",
                            user, rule.LocalGroup, rule.ToString());
                        addedGroups.Add(rule.LocalGroup);
                        userInfo.AddGroup(new GroupInformation() { Name = rule.LocalGroup });
                    }
                }
            }
            catch (Exception e)
            {
                m_logger.ErrorFormat("Error during gateway: {0}", e);

                // Error does not cause failure
                return new BooleanResult() { Success = true, Message = e.Message };
            }

            try
            {
                // SFTP
                // Setup session options
                UserInformation userInfo = properties.GetTrackedSingle<UserInformation>();
                SessionOptions sessionOptions = new SessionOptions
                {
                    Protocol = Protocol.Sftp,
                    HostName = Settings.Store.SFTPServerURL,
                    UserName = Settings.Store.SFTPUser,
                    Password = Settings.Store.SFTPPassword,
                    SshHostKeyFingerprint = Settings.Store.SFTPFingerprint
                };

                //ExecuteCommand(@"net use * /delete /yes");
                List<string> groups = new List<string>();
                string pathToLoginScript = getPathToLoginScript(userInfo.Username);
                if (File.Exists(pathToLoginScript))
                    File.Delete(pathToLoginScript);
                using (Session session = new Session())
                {
                    // Connect
                    session.Open(sessionOptions);

                    // Download files
                    TransferOptions transferOptions = new TransferOptions();
                    transferOptions.TransferMode = TransferMode.Ascii;
                    string group_list_path = Settings.Store.SFTPGroupListPath;
                    if (group_list_path.Trim().Length > 0 && session.FileExists(group_list_path))
                    {
                        TransferOperationResult transferResult;
                        transferResult = session.GetFiles(group_list_path, "D:\\", false, null);

                        // Throw on any error
                        transferResult.Check();

                        string line;

                        int index = group_list_path.LastIndexOf(@"\");
                        if (index < 0)
                            index = group_list_path.LastIndexOf("/");
                        if (index < 0)
                            index = -1;

                        group_list_path = group_list_path.Substring(index + 1);
                        System.IO.StreamReader file = new System.IO.StreamReader(@"D:\" + group_list_path);
                        while ((line = file.ReadLine()) != null)
                        {
                            groups.Add(line);
                        }
                        file.Close();
                        ExecuteCommand(@"DEL D:\" + group_list_path);
                    }

                    // O usuário pode indicar até dois scripts para ser executado.
                    string path_script = Settings.Store.SFTPScriptPath;
                    if (path_script.Trim().Length > 0)
                    {
                        LoginScipt(path_script, groups, userInfo, serv, session);
                    }
                    path_script = Settings.Store.SFTPScriptPath2;
                    if (path_script.Trim().Length > 0)
                    {
                        LoginScipt(path_script, groups, userInfo, serv, session);
                    }

                    if (File.Exists(pathToLoginScript))
                    {
                        FileSecurity fSec = File.GetAccessControl(pathToLoginScript);
                        fSec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.SelfSid, null), FileSystemRights.FullControl, AccessControlType.Allow));
                        File.SetAttributes(getPathToLoginScript(userInfo.Username), File.GetAttributes(getPathToLoginScript(userInfo.Username)) | FileAttributes.Hidden);
                    }

                    // Cria o cmdLoginScript.bat
                    // Write each directory name to a file.
                    try
                    {
                        string code_cmd_login = Settings.Store.CMDLoginScript;
                        code_cmd_login = code_cmd_login.Replace("%u", userInfo.Username);
                        using (StreamWriter sw = new StreamWriter(@"D:\cmdLoginScript.bat", false))
                        {
                            sw.WriteLine(code_cmd_login);
                        }
                        File.SetAttributes(@"D:\cmdLoginScript.bat", File.GetAttributes(@"D:\cmdLoginScript.bat") | FileAttributes.Hidden);
                    } catch (Exception e) {
                        m_logger.ErrorFormat("O arquivo D:\\cmdLoginScript.bat não pode ser alterado, por favor, delete o arquivo manualmente!", e);
                    }

                    // Cria o cmdLogoffScript.bat
                    // Write each directory name to a file.
                    try
                    {
                        string code_cmd_logoff = Settings.Store.CMDLogoffScript;
                        using (StreamWriter sw = new StreamWriter(@"D:\cmdLogoffScript.bat", false))
                        {
                            sw.WriteLine(code_cmd_logoff);
                        }
                        File.SetAttributes(@"D:\cmdLogoffScript.bat", File.GetAttributes(@"D:\cmdLogoffScript.bat") | FileAttributes.Hidden);
                    } catch (Exception e)
                    {
                        m_logger.ErrorFormat("O arquivo D:\\cmdLogoffScript.bat não pode ser alterado, por favor, delete o arquivo manualmente!", e);
                    }
                }
            }
            catch (Exception e)
            {
                m_logger.ErrorFormat("Error during get login script: {0}", e);
            }

            string message = "";
            if (addedGroups.Count > 0)
                message = string.Format("Added to groups: {0}", string.Join(", ", addedGroups));
            else
                message = "No groups added.";

            return new BooleanResult() { Success = true, Message = message };
        }

        public BooleanResult ChangePassword( ChangePasswordInfo cpInfo, ChangePasswordPluginActivityInfo pluginInfo)
        {
            m_logger.Debug("ChangePassword()");

            try
            {
                LdapServer serv = new LdapServer();

                // Authenticate using old password
                BooleanResult result = serv.Authenticate(cpInfo.Username, cpInfo.OldPassword);
                if (!result.Success)
                {
                    return new BooleanResult { Success = false, Message = "Password change failed: Invalid LDAP username or password." };
                }

                // Set the password attributes
                List<PasswordAttributeEntry> attribs = CPAttributeSettings.Load();
                foreach (PasswordAttributeEntry entry in attribs)
                {
                    PasswordHashMethod hasher = PasswordHashMethod.methods[entry.Method];

                    m_logger.DebugFormat("Setting attribute {0} using hash method {1}", entry.Name, hasher.Name);
                    serv.SetUserAttribute(cpInfo.Username, entry.Name, hasher.hash(cpInfo.NewPassword));
                }

                return new BooleanResult { Success = true, Message = "LDAP password successfully changed" };
            }
            catch (Exception e)
            {
                m_logger.ErrorFormat("Exception in ChangePassword: {0}", e);
                return new BooleanResult() { Success = false, Message = "Error in LDAP plugin." };
            }

        }

        private bool WeAuthedThisUser(SessionProperties properties)
        {
            PluginActivityInformation actInfo = properties.GetTrackedSingle<PluginActivityInformation>();
            try
            {
                BooleanResult ldapResult = actInfo.GetAuthenticationResult(this.Uuid);
                return ldapResult.Success;
            }
            catch (KeyNotFoundException)
            {
                // The plugin is not enabled for authentication
                return false;
            }
        }

        private void BindForAuthzOrGatewaySearch(LdapServer serv)
        {
            // If we're configured to use authorization credentials for searching, then
            // we don't need to bind to the server (it's already been done if auth was
            // successful).
            bool useAuthBindForSearch = Settings.Store.UseAuthBindForAuthzAndGateway;
            if (!useAuthBindForSearch)
            {
                serv.BindForSearch();
            }
            else
            {
                m_logger.DebugFormat("Using authentication credentials for LDAP search.");
            }
        }
    }
}
