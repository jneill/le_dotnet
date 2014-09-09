namespace Logentries.Core
{
    using System;
    using System.Collections.Concurrent;
    using System.Diagnostics;
    using System.Linq;
    using System.Threading;
    using System.Threading.Tasks;

    public class LeLogger : IDisposable
    {
        private const int QueueSize = 32768;

        private static readonly ConcurrentBag<BlockingCollection<string>> AllQueues = new ConcurrentBag<BlockingCollection<string>>();

        private readonly BlockingCollection<string> queue;

        private readonly LeClient client;

        private bool running;

        private CancellationTokenSource cancellationTokenSource;

        public LeLogger(LeClient client)
        {
            this.client = client;

            queue = new BlockingCollection<string>(QueueSize);
            AllQueues.Add(queue);
        }

        public static LeLogger CreateTokenBasedLogger(Guid token, bool? useSsl = null, LeMessageFormatter formatter = null)
        {
            return new LeLogger(
                new LeClient(
                    address: LeConfiguration.DefaultAddress,
                    port: useSsl == true ? LeConfiguration.DefaultSslPort : LeConfiguration.DefaultPort,
                    sslCertificate: useSsl == true ? LeConfiguration.DefaultSslCertificate : null,
                    token: token,
                    formatter: formatter));
        }

        public static LeLogger CreateDataHubLogger(string address, int port, LeMessageFormatter formatter = null)
        {
            return new LeLogger(new LeClient(address, port, formatter: formatter));
        }

        /// <summary>
        /// Determines if the queue is empty after waiting the specified waitTime.
        /// Returns true or false if the underlying queues are empty.
        /// </summary>
        /// <param name="waitTime">The length of time the method should block before giving up waiting for it to empty.</param>
        /// <returns>True if the queue is empty, false if there are still items waiting to be written.</returns>
        public static bool AreAllQueuesEmpty(TimeSpan waitTime)
        {
            var result = AreAllQueuesEmptyAsync(waitTime);
            result.Wait();
            return result.Result;
        }

        public static async Task<bool> AreAllQueuesEmptyAsync(TimeSpan waitTime)
        {
            var start = DateTime.UtcNow;

            while (DateTime.UtcNow.Subtract(start) > waitTime)
            {
                if (AllQueues.All(x => x.Count == 0))
                {
                    return true;
                }

                await Task.Delay(100);
            }

            return AllQueues.All(x => x.Count == 0);
        }

        public void Send(string message)
        {
            if (!queue.TryAdd(message))
            {
                queue.Take();

                if (!queue.TryAdd(message))
                {
                    Debug.WriteLine("Logentries buffer queue overflow. Message dropped");
                }
            }
        }

        public void Run()
        {
            if (running)
            {
                return;
            }

            cancellationTokenSource = new CancellationTokenSource();

            Task.Run(async () =>
            {
                while (running)
                {
                    try
                    {
                        var message = queue.Take();
                        await client.SendAsync(message, cancellationTokenSource.Token);
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine("Error communicating with Logentries. Message dropped. " + e);
                    }
                }
            });

            running = true;
        }

        public void Stop()
        {
            cancellationTokenSource.Cancel();
            running = false;
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
                Stop();

                queue.Dispose();
                client.Dispose();

                if (cancellationTokenSource != null)
                {
                    cancellationTokenSource.Dispose();
                }
            }
        }
    }
}
