namespace Logentries.Core
{
    using System;
    using System.Diagnostics;
    using System.IO;
    using System.Net.Security;
    using System.Net.Sockets;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading;
    using System.Threading.Tasks;

    public class TcpConnection : IDisposable
    {
        private static readonly TimeSpan MinReconnectDelay = TimeSpan.FromMilliseconds(100);

        private static readonly TimeSpan MaxReconnectDelay = TimeSpan.FromSeconds(10);

        private readonly Random random = new Random();

        private readonly string hostname;

        private readonly int port;

        private readonly X509Certificate2 sslCertificate;

        private TcpClient client;

        private Stream stream;

        public TcpConnection(
            string hostname,
            int port,
            X509Certificate2 sslCertificate = null)
        {
            this.hostname = hostname;
            this.port = port;
            this.sslCertificate = sslCertificate;
        }

        public async Task SendAsync(byte[] data, CancellationToken cancellationToken)
        {
            if (client == null || stream == null)
            {
                await OpenAsync();
            }

            Debug.Assert(client != null && stream != null, "Connection must be established");

            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    await stream.WriteAsync(data, 0, data.Length, cancellationToken);
                    await stream.FlushAsync(cancellationToken);
                    return;
                }
                catch (IOException e)
                {
                    Debug.WriteLine("LE: Unable to write to Logentries, will retry: " + e);
                    ReopenAsync(cancellationToken).Wait(cancellationToken);
                }
            }
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
                Close();
            }
        }

        private void Close()
        {
            if (stream != null)
            {
                stream.Close();
                client = null;
            }

            if (client != null)
            {
                client.Close();
                client = null;
            }
        }

        private async Task ReopenAsync(CancellationToken cancellationToken)
        {
            Close();

            var delay = MinReconnectDelay;

            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    await OpenAsync();
                    return;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine("LE: Unable to connect to Logentries, will retry: " + " " + ex);
                }

                delay = delay.Add(delay);
                if (delay > MaxReconnectDelay)
                {
                    delay = MaxReconnectDelay;
                }

                var wait = delay.Milliseconds + random.Next(delay.Milliseconds);
                await Task.Delay(wait, cancellationToken);
            }
        }

        private async Task OpenAsync()
        {
            if (client != null || stream != null)
            {
                return;
            }

            try
            {
                client = new TcpClient(hostname, port) { NoDelay = true };
                stream = client.GetStream();

                if (sslCertificate != null)
                {
                    var sslStream = new SslStream(
                        innerStream: stream,
                        leaveInnerStreamOpen: false,
                        userCertificateValidationCallback: (sender, cert, chain, errors) =>
                            cert.GetCertHashString() == sslCertificate.GetCertHashString());

                    await sslStream.AuthenticateAsClientAsync(hostname);

                    stream = sslStream;
                }
            }
            catch (Exception e)
            {
                Close();
                throw new IOException("An error occurred while opening the connection", e);
            }
        }
    }
}
