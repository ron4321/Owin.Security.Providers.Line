using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Newtonsoft.Json.Linq;
using Microsoft.Owin.Security.Provider;

namespace Owin.Security.Providers.Line.Provider
{
    public class LineAuthenticatedContext : BaseContext
    {
        public LineAuthenticatedContext(IOwinContext context, JObject user, string accessToken) 
            : base(context)
        {
            User = user;
            AccessToken = accessToken;

            userId = TryGetValue(user, "userId");
            DisplayName = TryGetValue(user, "displayName");
            ProfilePicture = TryGetValue(user, "pictureUrl");
            StatusMessage = TryGetValue(user, "statusMessage");

        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// Contains the Line user obtained from token ednpoint
        /// </remarks>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the Line access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the Line user ID
        /// </summary>
        public string userId { get; private set; }

        /// <summary>
        /// Gets the display name
        /// </summary>
        public string DisplayName { get; private set; }


        /// <summary>
        /// Gets the Line users profile picture
        /// </summary>
        public string ProfilePicture { get; private set; }

        /// <summary>
        /// Gets the Line users status message
        /// </summary>
        public string StatusMessage { get; private set; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }

        private static string TryGetValue(JObject user, string propertyName)
        {
            JToken value;
            return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }
    }
}