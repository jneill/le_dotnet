// ReSharper disable once CheckNamespace
namespace log4net.Appender
{
    using log4net.Core;

    using Logentries.Core;

    public class LogentriesAppender : AppenderSkeleton
    {
        private LeLogger logger;

        public string Token { get; set; }

        public bool ImmediateFlush { get; set; }

        public bool Debug { get; set; }

        public bool UseSsl { get; set; }

        public bool IsUsingDataHub { get; set; }

        public string DataHubAddress { get; set; }

        public int DataHubPort { get; set; }

        public bool LogHostname { get; set; }

        public string HostName { get; set; }

        public string LogId { get; set; }

        protected override bool RequiresLayout
        {
            get { return true; }
        }

        protected override void Append(LoggingEvent loggingEvent)
        {
            if (logger == null)
            {
                logger = CreateLogger();
                logger.Run();
            }

            var renderedEvent = RenderLoggingEvent(loggingEvent);
            logger.Send(renderedEvent);
        }

        protected override void Append(LoggingEvent[] loggingEvents)
        {
            foreach (var logEvent in loggingEvents)
            {
                this.Append(logEvent);
            }
        }

        protected override void OnClose()
        {
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
                : LeLogger.CreateTokenBasedLogger(LeConfiguration.GetValidToken(Token), UseSsl, formatter);
        }
    }
}
