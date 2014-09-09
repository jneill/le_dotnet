namespace Logentries.Core
{
    using System;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;

    public class LeClient : IDisposable
    {
        private const string LineSeparator = "\u2028";

        private static readonly string[] NewlineSequences = { "\r\n", "\n" };

        private static readonly Encoding Encoding = Encoding.UTF8;

        private readonly string tokenString;

        private readonly LeMessageFormatter formatter;

        private readonly TcpConnection connection;

        public LeClient(
            string address,
            int port,
            X509Certificate2 sslCertificate = null,
            Guid? token = null,
            LeMessageFormatter formatter = null)
            : this(new TcpConnection(address, port, sslCertificate), token, formatter)
        {
        }

        public LeClient(
            TcpConnection connection,
            Guid? token = null,
            LeMessageFormatter formatter = null)
        {
            this.connection = connection;
            this.formatter = formatter ?? new LeMessageFormatter();
            this.tokenString = token != null ? token.ToString() : string.Empty;
        }

        public async Task SendAsync(string message, CancellationToken cancellationToken)
        {
            message = formatter.Format(message);
            var data = Encoding.GetBytes(tokenString + EncodeNewlines(message) + "\n");
            await connection.SendAsync(data, cancellationToken);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                connection.Dispose();
            }
        }

        private string EncodeNewlines(string message)
        {
            foreach (string newline in NewlineSequences)
            {
                message = message.Replace(newline, LineSeparator);
            }

            return message;
        }
    }
}
