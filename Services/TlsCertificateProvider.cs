using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace NetworkSentinel.Services;

/// <summary>
/// Loads the web console's TLS certificate and re-reads it from disk when it changes,
/// so an ACME renewal (acme.sh / certbot) is picked up without restarting the service.
/// Accepts PEM (fullchain + private key) or PKCS#12 (.pfx / .p12).
/// </summary>
public sealed class TlsCertificateProvider : IDisposable
{
    /// <summary>How often the certificate files are re-stat'd. Renewals are rare; this is cheap either way.</summary>
    private static readonly TimeSpan ReloadCheckInterval = TimeSpan.FromMinutes(5);

    private readonly string _certPath;
    private readonly string _keyPath;
    private readonly string _pfxPassword;
    private readonly object _gate = new();

    private X509Certificate2? _certificate;
    private DateTime _loadedStampUtc = DateTime.MinValue;
    private DateTime _lastCheckUtc = DateTime.MinValue;

    public TlsCertificateProvider(string certPath, string keyPath, string pfxPassword = "")
    {
        _certPath = (certPath ?? "").Trim();
        _keyPath = (keyPath ?? "").Trim();
        _pfxPassword = pfxPassword ?? "";
    }

    /// <summary>Human-readable state for the console's settings page and the startup banner.</summary>
    public string Status { get; private set; } = "HTTPS: not configured";

    /// <summary>The certificate Kestrel should present, or null when it cannot be loaded.</summary>
    public X509Certificate2? Current
    {
        get
        {
            lock (_gate)
            {
                var now = DateTime.UtcNow;
                if (_certificate != null && now - _lastCheckUtc < ReloadCheckInterval)
                    return _certificate;

                _lastCheckUtc = now;
                var stamp = NewestWriteTimeUtc();
                if (_certificate != null && stamp == _loadedStampUtc)
                    return _certificate;

                if (TryLoad(_certPath, _keyPath, _pfxPassword, out var loaded, out var error))
                {
                    var previous = _certificate;
                    _certificate = loaded;
                    _loadedStampUtc = stamp;
                    Status = Describe(loaded!);
                    if (previous != null && !ReferenceEquals(previous, loaded))
                        previous.Dispose();
                }
                else if (_certificate == null)
                {
                    Status = $"HTTPS: certificate problem — {error}";
                }
                // A failed reload keeps serving the previously loaded certificate.

                return _certificate;
            }
        }
    }

    /// <summary>Load without caching — used at startup so a bad path fails loudly before binding.</summary>
    public static bool TryLoad(string certPath, string keyPath, string pfxPassword,
        out X509Certificate2? certificate, out string error)
    {
        certificate = null;
        error = "";

        if (string.IsNullOrWhiteSpace(certPath))
        {
            error = "no certificate path set";
            return false;
        }

        if (!File.Exists(certPath))
        {
            error = $"certificate file not found: {certPath}";
            return false;
        }

        try
        {
            X509Certificate2 loaded;
            var isPkcs12 = certPath.EndsWith(".pfx", StringComparison.OrdinalIgnoreCase) ||
                           certPath.EndsWith(".p12", StringComparison.OrdinalIgnoreCase);

            if (isPkcs12)
            {
                loaded = new X509Certificate2(certPath, pfxPassword);
            }
            else
            {
                var key = string.IsNullOrWhiteSpace(keyPath) ? certPath : keyPath;
                if (!File.Exists(key))
                {
                    error = $"private key file not found: {key}";
                    return false;
                }

                using var pem = X509Certificate2.CreateFromPemFile(certPath, key);
                // PEM-derived certs carry an ephemeral key that some TLS stacks refuse to use.
                // Round-tripping through PKCS#12 gives a handle SslStream always accepts.
                loaded = new X509Certificate2(pem.Export(X509ContentType.Pkcs12));
            }

            if (!loaded.HasPrivateKey)
            {
                loaded.Dispose();
                error = "certificate has no private key (point --tls-key at the private key file)";
                return false;
            }

            certificate = loaded;
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static string Describe(X509Certificate2 cert)
    {
        var name = cert.GetNameInfo(X509NameType.DnsName, forIssuer: false);
        if (string.IsNullOrEmpty(name))
            name = cert.Subject;

        var expiresIn = cert.NotAfter - DateTime.Now;
        var expiry = expiresIn <= TimeSpan.Zero
            ? $"EXPIRED {cert.NotAfter:yyyy-MM-dd}"
            : $"expires {cert.NotAfter:yyyy-MM-dd} ({(int)expiresIn.TotalDays}d)";

        var issuer = cert.GetNameInfo(X509NameType.SimpleName, forIssuer: true);
        var selfSigned = string.Equals(cert.Subject, cert.Issuer, StringComparison.Ordinal);

        return $"HTTPS: {name} — {expiry}" +
               (selfSigned ? " — self-signed (browsers will warn)" : $" — issued by {issuer}");
    }

    private DateTime NewestWriteTimeUtc()
    {
        var newest = DateTime.MinValue;
        foreach (var p in new[] { _certPath, _keyPath })
        {
            if (string.IsNullOrWhiteSpace(p))
                continue;
            try
            {
                if (File.Exists(p))
                {
                    var t = File.GetLastWriteTimeUtc(p);
                    if (t > newest) newest = t;
                }
            }
            catch
            {
                // unreadable — treated as unchanged
            }
        }
        return newest;
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _certificate?.Dispose();
            _certificate = null;
        }
    }
}
