using FluentAssertions;
using Jellyfin.Plugin.SSO_Auth;

namespace SSO_Auth.Tests;

public class WebResponseTests
{
    [Fact]
    public void Generator_ContainsJsonConfigElement()
    {
        var html = WebResponse.Generator("testdata", "myprovider", "https://jellyfin.example.com", "OID");

        html.Should().Contain("<script type=\"application/json\" id=\"sso-config\">");
    }

    [Fact]
    public void Generator_EscapesProviderWithSingleQuote()
    {
        // XSS payload: provider name containing a JS string breakout
        var html = WebResponse.Generator("testdata", "';alert(1);//", "https://jellyfin.example.com", "OID");

        // The raw payload should NOT appear unescaped in the output
        html.Should().NotContain("';alert(1);//");
        // The JSON serializer escapes ' as \u0027
        html.Should().Contain("\\u0027");
    }

    [Fact]
    public void Generator_EscapesProviderWithAngleBrackets()
    {
        var html = WebResponse.Generator("testdata", "<script>alert(1)</script>", "https://jellyfin.example.com", "OID");

        // Angle brackets should be escaped in JSON as \u003C / \u003E
        html.Should().NotContain("<script>alert(1)</script>");
        html.Should().Contain("\\u003C");
    }

    [Fact]
    public void Generator_EscapesDataParameter()
    {
        // SAML data could contain malicious content
        var html = WebResponse.Generator("';document.cookie;//", "myprovider", "https://jellyfin.example.com", "SAML");

        html.Should().NotContain("';document.cookie;//");
    }

    [Fact]
    public void Generator_SerializesIsLinkingAsBoolean()
    {
        var htmlLinking = WebResponse.Generator("data", "prov", "https://example.com", "OID", isLinking: true);
        var htmlNotLinking = WebResponse.Generator("data", "prov", "https://example.com", "OID", isLinking: false);

        // JSON should contain "isLinking":true or "isLinking":false
        htmlLinking.Should().Contain("\"isLinking\":true");
        htmlNotLinking.Should().Contain("\"isLinking\":false");
    }

    [Fact]
    public void Generator_UsesConfigObjectInJavaScript()
    {
        var html = WebResponse.Generator("mydata", "myprovider", "https://jellyfin.example.com", "OID");

        // The JS should read from ssoConfig, not from inline C# interpolation
        html.Should().Contain("ssoConfig.data");
        html.Should().Contain("ssoConfig.baseUrl");
        html.Should().Contain("ssoConfig.provider");
        html.Should().Contain("ssoConfig.mode");
        html.Should().Contain("ssoConfig.isLinking");
    }

    [Fact]
    public void Generator_HandlesPunycodeDomain()
    {
        // Non-ASCII domain should be converted to punycode
        var html = WebResponse.Generator("data", "prov", "https://jëllyfin.example.com", "OID");

        // Should contain punycode-encoded domain
        html.Should().Contain("xn--jllyfin-9xa.example.com");
    }

    [Fact]
    public void Generator_ProducesValidHtml()
    {
        var html = WebResponse.Generator("data", "prov", "https://example.com", "OID");

        html.Should().StartWith("<!DOCTYPE html>");
        html.Should().Contain("</html>");
        html.Should().Contain("<iframe id='iframe-main'");
    }
}
