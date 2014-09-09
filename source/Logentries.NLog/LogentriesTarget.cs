// ReSharper disable once CheckNamespace
namespace NLog.Targets
{
    using Logentries.Core;

    [Target("Logentries")]
    public sealed class LogentriesTarget : TargetWithLayout
    {
        private LeLogger logger;

        public bool Debug { get; set; }

        public bool IsUsingDataHub { get; set; }

        public string DataHubAddress { get; set; }

        public int DataHubPort { get; set; }

        public string Token { get; set; }

        public bool Ssl { get; set; }

        public bool LogHostname { get; set; }

        public string HostName { get; set; }

        public string LogId { get; set; }

        public bool KeepConnection { get; set; }

        protected override void Write(LogEventInfo logEvent)
        {
            if (logger == null)
            {
                logger = CreateLogger();
                logger.Run();
            }

            var message = ToMessage(logEvent);
            logger.Send(message);
        }

        protected override void CloseTarget()
        {
            base.CloseTarget();

            if (logger != null)
            {
                logger.Stop();
            }
        }

        private LeLogger CreateLogger()
        {
            var formatter = new LeMessageFormatter(
                logId: LogId,
                hostname: LogHostname ? LeConfiguration.GetValidHostName(HostName) : null);

            return IsUsingDataHub
                ? LeLogger.CreateDataHubLogger(DataHubAddress, DataHubPort, formatter)
                : LeLogger.CreateTokenBasedLogger(LeConfiguration.GetValidToken(Token), Ssl, formatter);
        }

        private string ToMessage(LogEventInfo logEvent)
        {
            var renderedEvent = Layout.Render(logEvent);
            return logEvent.Exception != null
                ? renderedEvent + ", " + logEvent.Exception
                : renderedEvent;
        }
    }
}
