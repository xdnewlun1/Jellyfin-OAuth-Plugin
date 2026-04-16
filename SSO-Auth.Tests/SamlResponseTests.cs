using FluentAssertions;
using Jellyfin.Plugin.SSO_Auth;
using SSO_Auth.Tests.Helpers;

namespace SSO_Auth.Tests;

public class SamlResponseTests
{
    [Fact]
    public void IsValid_ReturnsFalse_WhenNoSignature()
    {
        var base64 = TestSamlHelper.CreateUnsignedResponseBase64("testuser");
        var response = new Response(TestSamlHelper.CertificateBase64, base64);

        response.IsValid().Should().BeFalse();
    }

    [Fact]
    public void IsValid_ReturnsTrue_WhenSignatureIsValid()
    {
        var base64 = TestSamlHelper.CreateSignedResponseBase64("testuser");
        var response = new Response(TestSamlHelper.CertificateBase64, base64);

        response.IsValid().Should().BeTrue();
    }

    [Fact]
    public void IsValid_ReturnsFalse_WhenExpired()
    {
        var base64 = TestSamlHelper.CreateSignedResponseBase64(
            notOnOrAfter: DateTime.UtcNow.AddHours(-1));
        var response = new Response(TestSamlHelper.CertificateBase64, base64);

        response.IsValid().Should().BeFalse();
    }

    [Fact]
    public void IsValid_ReturnsFalse_WhenNotBeforeIsInTheFuture()
    {
        var base64 = TestSamlHelper.CreateSignedResponseBase64(
            notBefore: DateTime.UtcNow.AddHours(1));
        var response = new Response(TestSamlHelper.CertificateBase64, base64);

        response.IsValid().Should().BeFalse();
    }

    [Fact]
    public void IsValid_ReturnsFalse_WhenAudienceDoesNotMatch()
    {
        var base64 = TestSamlHelper.CreateSignedResponseBase64(
            audience: "https://wrong-audience.example.com");
        var response = new Response(TestSamlHelper.CertificateBase64, base64);

        response.IsValid("https://expected-audience.example.com", null).Should().BeFalse();
    }

    [Fact]
    public void IsValid_ReturnsTrue_WhenAudienceMatches()
    {
        var base64 = TestSamlHelper.CreateSignedResponseBase64(
            audience: "https://my-jellyfin.example.com");
        var response = new Response(TestSamlHelper.CertificateBase64, base64);

        response.IsValid("https://my-jellyfin.example.com", null).Should().BeTrue();
    }

    [Fact]
    public void IsValid_ReturnsFalse_WhenRecipientDoesNotMatch()
    {
        var base64 = TestSamlHelper.CreateSignedResponseBase64(
            recipient: "https://wrong-recipient.example.com/acs");
        var response = new Response(TestSamlHelper.CertificateBase64, base64);

        response.IsValid(null, "https://expected-recipient.example.com/acs").Should().BeFalse();
    }

    [Fact]
    public void IsValid_ReturnsTrue_WhenRecipientMatches()
    {
        var base64 = TestSamlHelper.CreateSignedResponseBase64(
            recipient: "https://my-jellyfin.example.com/sso/SAML/post/myidp");
        var response = new Response(TestSamlHelper.CertificateBase64, base64);

        response.IsValid(null, "https://my-jellyfin.example.com/sso/SAML/post/myidp").Should().BeTrue();
    }

    [Fact]
    public void IsValid_SkipsAudienceCheck_WhenExpectedAudienceIsNull()
    {
        var base64 = TestSamlHelper.CreateSignedResponseBase64(
            audience: "https://any-audience.example.com");
        var response = new Response(TestSamlHelper.CertificateBase64, base64);

        response.IsValid(null, null).Should().BeTrue();
    }

    [Fact]
    public void GetNameID_ReturnsCorrectValue()
    {
        var base64 = TestSamlHelper.CreateSignedResponseBase64(nameId: "john.doe");
        var response = new Response(TestSamlHelper.CertificateBase64, base64);

        response.GetNameID().Should().Be("john.doe");
    }

    [Fact]
    public void GetCustomAttribute_ThrowsOnSingleQuote()
    {
        var base64 = TestSamlHelper.CreateSignedResponseBase64();
        var response = new Response(TestSamlHelper.CertificateBase64, base64);

        var act = () => response.GetCustomAttribute("role' or '1'='1");
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void GetCustomAttributes_ThrowsOnSingleQuote()
    {
        var base64 = TestSamlHelper.CreateSignedResponseBase64();
        var response = new Response(TestSamlHelper.CertificateBase64, base64);

        var act = () => response.GetCustomAttributes("x'");
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void GetCustomAttribute_ReturnsNull_WhenNotPresent()
    {
        var base64 = TestSamlHelper.CreateSignedResponseBase64();
        var response = new Response(TestSamlHelper.CertificateBase64, base64);

        response.GetCustomAttribute("nonexistent").Should().BeNull();
    }

    [Fact]
    public void GetCustomAttributes_ReturnsValues_WhenPresent()
    {
        var attrs = new Dictionary<string, string[]>
        {
            { "Role", new[] { "admin", "user" } }
        };
        var base64 = TestSamlHelper.CreateSignedResponseBase64(attributes: attrs);
        var response = new Response(TestSamlHelper.CertificateBase64, base64);

        var roles = response.GetCustomAttributes("Role");
        roles.Should().Contain("admin");
        roles.Should().Contain("user");
        roles.Should().HaveCount(2);
    }

    [Fact]
    public void GetCustomAttributes_ReturnsEmptyList_WhenNotPresent()
    {
        var base64 = TestSamlHelper.CreateSignedResponseBase64();
        var response = new Response(TestSamlHelper.CertificateBase64, base64);

        response.GetCustomAttributes("Role").Should().BeEmpty();
    }
}
