using System;

namespace Owin.Security.Providers.Line
{
    public static class LineAuthenticationExtensions
    {
        public static IAppBuilder UseLineAuthentication(this IAppBuilder app,
            LineAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            app.Use(typeof(LineAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseLineAuthentication(this IAppBuilder app, string channelId, string channelSecret)
        {
            return app.UseLineAuthentication(new LineAuthenticationOptions
            {
                ChannelId = channelId,
                ChannelSecret = channelSecret
            });
        }
    }
}
