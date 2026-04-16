using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace SSO_Auth.Tests.Helpers;

/// <summary>
/// Generates signed SAML response XML for testing purposes.
/// </summary>
internal static class TestSamlHelper
{
    private static readonly Lazy<(X509Certificate2 Cert, string CertBase64)> CachedCert = new(() =>
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=TestSAML", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));
        var certBytes = cert.Export(X509ContentType.Cert);
        return (cert, Convert.ToBase64String(certBytes));
    });

    /// <summary>
    /// Gets a self-signed test certificate.
    /// </summary>
    public static X509Certificate2 Certificate => CachedCert.Value.Cert;

    /// <summary>
    /// Gets the test certificate as a Base64 string (for use in config).
    /// </summary>
    public static string CertificateBase64 => CachedCert.Value.CertBase64;

    /// <summary>
    /// Creates a signed SAML Response XML string, Base64-encoded.
    /// </summary>
    public static string CreateSignedResponseBase64(
        string nameId = "testuser",
        string? audience = null,
        string? recipient = null,
        DateTime? notOnOrAfter = null,
        DateTime? notBefore = null,
        Dictionary<string, string[]>? attributes = null)
    {
        var xml = CreateSignedResponseXml(nameId, audience, recipient, notOnOrAfter, notBefore, attributes);
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(xml));
    }

    /// <summary>
    /// Creates an unsigned SAML Response XML string, Base64-encoded.
    /// </summary>
    public static string CreateUnsignedResponseBase64(string nameId = "testuser")
    {
        var xml = BuildSamlXml(nameId, null, null, DateTime.UtcNow.AddHours(1), null, null);
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(xml));
    }

    /// <summary>
    /// Creates a signed SAML Response raw XML string.
    /// </summary>
    public static string CreateSignedResponseXml(
        string nameId = "testuser",
        string? audience = null,
        string? recipient = null,
        DateTime? notOnOrAfter = null,
        DateTime? notBefore = null,
        Dictionary<string, string[]>? attributes = null)
    {
        notOnOrAfter ??= DateTime.UtcNow.AddHours(1);
        var rawXml = BuildSamlXml(nameId, audience, recipient, notOnOrAfter.Value, notBefore, attributes);
        return SignXml(rawXml);
    }

    private static string BuildSamlXml(
        string nameId,
        string? audience,
        string? recipient,
        DateTime notOnOrAfter,
        DateTime? notBefore,
        Dictionary<string, string[]>? attributes)
    {
        var responseId = "_" + Guid.NewGuid().ToString();
        var assertionId = "_" + Guid.NewGuid().ToString();
        var issueInstant = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
        var notOnOrAfterStr = notOnOrAfter.ToString("yyyy-MM-ddTHH:mm:ssZ");

        var conditionsAttrs = $@"NotOnOrAfter=""{notOnOrAfterStr}""";
        if (notBefore.HasValue)
        {
            conditionsAttrs += $@" NotBefore=""{notBefore.Value.ToString("yyyy-MM-ddTHH:mm:ssZ")}""";
        }

        var audienceXml = string.IsNullOrEmpty(audience)
            ? string.Empty
            : $@"<saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction>";

        var recipientAttr = string.IsNullOrEmpty(recipient)
            ? string.Empty
            : $@" Recipient=""{recipient}""";

        var attributeStatementXml = string.Empty;
        if (attributes != null && attributes.Count > 0)
        {
            var attrXml = new StringBuilder();
            attrXml.Append("<saml:AttributeStatement>");
            foreach (var kvp in attributes)
            {
                attrXml.Append($@"<saml:Attribute Name=""{kvp.Key}"">");
                foreach (var val in kvp.Value)
                {
                    attrXml.Append($@"<saml:AttributeValue>{val}</saml:AttributeValue>");
                }
                attrXml.Append("</saml:Attribute>");
            }
            attrXml.Append("</saml:AttributeStatement>");
            attributeStatementXml = attrXml.ToString();
        }

        return $@"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""{responseId}"" Version=""2.0"" IssueInstant=""{issueInstant}"">
  <saml:Assertion xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""{assertionId}"" Version=""2.0"" IssueInstant=""{issueInstant}"">
    <saml:Issuer>https://test-idp.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID>{nameId}</saml:NameID>
      <saml:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"">
        <saml:SubjectConfirmationData NotOnOrAfter=""{notOnOrAfterStr}""{recipientAttr} />
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions {conditionsAttrs}>
      {audienceXml}
    </saml:Conditions>
    {attributeStatementXml}
  </saml:Assertion>
</samlp:Response>";
    }

    private static string SignXml(string xml)
    {
        var doc = new XmlDocument();
        doc.PreserveWhitespace = true;
        doc.LoadXml(xml);

        // Sign the Assertion element
        var assertionNode = doc.GetElementsByTagName("Assertion", "urn:oasis:names:tc:SAML:2.0:assertion")[0] as XmlElement
            ?? throw new InvalidOperationException("No Assertion element found");

        var signedXml = new SignedXml(doc);
        signedXml.SigningKey = Certificate.GetRSAPrivateKey();

        var reference = new Reference("#" + assertionNode.GetAttribute("ID"));
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigExcC14NTransform());
        signedXml.AddReference(reference);

        signedXml.ComputeSignature();
        var signatureElement = signedXml.GetXml();

        assertionNode.AppendChild(doc.ImportNode(signatureElement, true));

        return doc.OuterXml;
    }
}
