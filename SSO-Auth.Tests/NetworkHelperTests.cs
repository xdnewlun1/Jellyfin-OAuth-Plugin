using System.Net;
using FluentAssertions;
using Jellyfin.Plugin.SSO_Auth.Api;

namespace SSO_Auth.Tests;

public class NetworkHelperTests
{
    [Theory]
    [InlineData("127.0.0.1", true)]
    [InlineData("127.0.0.2", true)]
    [InlineData("10.0.0.1", true)]
    [InlineData("10.255.255.255", true)]
    [InlineData("172.16.0.1", true)]
    [InlineData("172.31.255.255", true)]
    [InlineData("192.168.0.1", true)]
    [InlineData("192.168.255.255", true)]
    [InlineData("169.254.1.1", true)]
    [InlineData("169.254.169.254", true)] // AWS metadata endpoint
    public void IsPrivateOrLoopbackAddress_ReturnsTrue_ForPrivateIPs(string ip, bool expected)
    {
        var address = IPAddress.Parse(ip);
        NetworkHelpers.IsPrivateOrLoopbackAddress(address).Should().Be(expected);
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("1.1.1.1")]
    [InlineData("172.15.255.255")] // Just below 172.16.0.0
    [InlineData("172.32.0.0")]     // Just above 172.31.255.255
    [InlineData("11.0.0.1")]
    [InlineData("192.167.1.1")]
    [InlineData("169.253.1.1")]
    [InlineData("93.184.216.34")]  // example.com
    public void IsPrivateOrLoopbackAddress_ReturnsFalse_ForPublicIPs(string ip)
    {
        var address = IPAddress.Parse(ip);
        NetworkHelpers.IsPrivateOrLoopbackAddress(address).Should().BeFalse();
    }

    [Fact]
    public void IsPrivateOrLoopbackAddress_ReturnsTrue_ForIPv6Loopback()
    {
        NetworkHelpers.IsPrivateOrLoopbackAddress(IPAddress.IPv6Loopback).Should().BeTrue();
    }

    [Fact]
    public void IsPrivateOrLoopbackAddress_ReturnsTrue_ForIPv6LinkLocal()
    {
        // fe80::1 is link-local
        var address = IPAddress.Parse("fe80::1");
        NetworkHelpers.IsPrivateOrLoopbackAddress(address).Should().BeTrue();
    }
}
