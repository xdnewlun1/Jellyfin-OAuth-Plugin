using System.Net;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Network utility methods for SSRF protection.
/// </summary>
internal static class NetworkHelpers
{
    /// <summary>
    /// Determines whether an IP address is a private, loopback, or link-local address.
    /// Used to block SSRF attempts targeting internal networks.
    /// </summary>
    /// <param name="address">The IP address to check.</param>
    /// <returns>True if the address is private, loopback, or link-local.</returns>
    internal static bool IsPrivateOrLoopbackAddress(IPAddress address)
    {
        if (IPAddress.IsLoopback(address) || address.IsIPv6LinkLocal || address.IsIPv6SiteLocal)
        {
            return true;
        }

        byte[] bytes = address.GetAddressBytes();
        return bytes.Length == 4 && (
            bytes[0] == 10 ||
            (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
            (bytes[0] == 192 && bytes[1] == 168) ||
            (bytes[0] == 169 && bytes[1] == 254));
    }
}
