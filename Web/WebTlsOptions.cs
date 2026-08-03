namespace NetworkSentinel.Web;

/// <summary>
/// TLS values supplied on the command line. Anything left null falls back to the saved
/// settings, so a one-off <c>--https</c> run does not rewrite the user's configuration.
/// </summary>
public sealed class WebTlsOptions
{
    public bool? Enabled { get; set; }
    public int? Port { get; set; }
    public string? CertPath { get; set; }
    public string? KeyPath { get; set; }
    public string? PfxPassword { get; set; }

    public bool HasAny => Enabled.HasValue || Port.HasValue ||
                          !string.IsNullOrWhiteSpace(CertPath) ||
                          !string.IsNullOrWhiteSpace(KeyPath) ||
                          !string.IsNullOrWhiteSpace(PfxPassword);
}
