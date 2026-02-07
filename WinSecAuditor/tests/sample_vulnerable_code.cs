// Example C# code with intentional security vulnerabilities
// FOR TESTING PURPOSES ONLY - DO NOT USE IN PRODUCTION

using System;
using System.Data.SqlClient;
using System.Web;
using System.IO;
using System.Security.Cryptography;
using System.Diagnostics;

namespace VulnerableApp
{
    public class SecurityIssuesDemo
    {
        // SQL Injection vulnerability
        public void UnsafeQuery(string userId)
        {
            string connectionString = "Server=localhost;Database=myDB;User Id=sa;Password=P@ssw0rd123;";
            using (SqlConnection conn = new SqlConnection(connectionString))
            {
                conn.Open();
                // VULNERABLE: String concatenation in SQL query
                string query = "SELECT * FROM Users WHERE UserId = '" + userId + "'";
                SqlCommand cmd = new SqlCommand(query, conn);
                cmd.ExecuteReader();
            }
        }

        // Hardcoded credentials
        private const string API_KEY = "sk_live_51H7xxxxxxxxxxxxxxxxxxx";
        private const string DATABASE_PASSWORD = "SuperSecret123!";
        
        // Weak cryptography
        public string WeakHash(string input)
        {
            // VULNERABLE: MD5 is cryptographically broken
            using (MD5 md5 = MD5.Create())
            {
                byte[] hash = md5.ComputeHash(System.Text.Encoding.UTF8.GetBytes(input));
                return BitConverter.ToString(hash);
            }
        }

        // Command injection
        public void ExecuteCommand(string filename)
        {
            // VULNERABLE: User input in process execution
            Process.Start("cmd.exe", "/c type " + filename);
        }

        // Path traversal
        public string ReadUserFile(string fileName)
        {
            // VULNERABLE: No path validation
            string content = File.ReadAllText("C:\\uploads\\" + fileName);
            return content;
        }

        // XSS vulnerability
        public void RenderUserInput(string userInput)
        {
            // VULNERABLE: Unencoded output
            HttpContext.Current.Response.Write("<div>" + userInput + "</div>");
        }

        // Empty catch block
        public void BadErrorHandling()
        {
            try
            {
                int result = 10 / 0;
            }
            catch (Exception ex)
            {
                // VULNERABLE: Swallowing exception
            }
        }

        // Memory leak - IDisposable not disposed
        public void ResourceLeak()
        {
            // VULNERABLE: FileStream not disposed
            FileStream fs = new FileStream("temp.txt", FileMode.Create);
            // Missing: using statement or fs.Dispose()
        }

        // Insecure random
        public int WeakRandom()
        {
            // VULNERABLE: Random is not cryptographically secure
            Random rnd = new Random();
            return rnd.Next();
        }

        // SSL/TLS validation disabled
        public void DisableSSLValidation()
        {
            // VULNERABLE: Disabling certificate validation
            System.Net.ServicePointManager.ServerCertificateValidationCallback = 
                (sender, cert, chain, errors) => true;
        }

        // Logging sensitive data
        public void LogCredentials(string username, string password)
        {
            // VULNERABLE: Logging sensitive information
            Console.WriteLine($"Login attempt: {username} / {password}");
        }

        // Thread safety issue
        private static int counter = 0;
        public void UnsafeIncrement()
        {
            // VULNERABLE: Race condition
            counter++;
        }

        // Lock on this
        public void BadLocking()
        {
            // VULNERABLE: Locking on this
            lock (this)
            {
                // Critical section
            }
        }

        // God class (too many responsibilities)
        public void DatabaseOperation() { }
        public void FileOperation() { }
        public void NetworkOperation() { }
        public void UIOperation() { }
        public void SecurityOperation() { }
        public void LoggingOperation() { }
        // ... many more methods indicating SRP violation
    }

    // Configuration example with issues
    public class AppConfig
    {
        // Hardcoded connection string with credentials
        public static string ConnectionString = 
            "Data Source=prod-server;Initial Catalog=MainDB;User ID=admin;Password=Admin@2024;";
        
        // Hardcoded API keys
        public static string StripeKey = "sk_live_xxxxxxxxxxxxxxxxxxxxxxxx";
        public static string AWSAccessKey = "AKIAIOSFODNN7EXAMPLE";
        public static string AWSSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    }
}
