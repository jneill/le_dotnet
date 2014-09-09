namespace Logentries.Core
{
    public class LeMessageFormatter
    {
        private static readonly char[] TrimChars = { '\r', '\n' };

        private readonly string prefix;

        public LeMessageFormatter(string logId = null, string hostname = null)
        {
            prefix = string.Empty;

            if (!string.IsNullOrWhiteSpace(logId))
            {
                prefix += logId + " ";
            }

            if (!string.IsNullOrWhiteSpace(hostname))
            {
                prefix += "HostName=" + hostname + " ";
            }
        }

        public string Format(string message)
        {
            return prefix + message.Trim(TrimChars);
        }
    }
}
