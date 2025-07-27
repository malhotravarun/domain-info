param (
    [Parameter(Mandatory=$true)]
    [string]$Domain,
    
    [int]$Port = 443
)

# -------------------------------
# 1️⃣ DNS Record Checks
# -------------------------------
$recordTypes = @("A", "AAAA", "MX", "NS", "CNAME", "TXT", "SOA")

Write-Host "`n🔍 Checking DNS records for domain: $Domain`n" -ForegroundColor Cyan

foreach ($type in $recordTypes) {
    Write-Host "➡️  Record Type: $type" -ForegroundColor Yellow
    Write-Host ""
    try {
        $results = Resolve-DnsName -Name $Domain -Type $type -ErrorAction Stop
        foreach ($result in $results) {
            switch ($type) {
                "A"      { Write-Host "  IP Address: $($result.IPAddress)" }
                "AAAA"   { Write-Host "  IPv6 Address: $($result.IPAddress)" }
                "MX"     { Write-Host "  Mail Exchange: $($result.MailExchange), Preference: $($result.Preference)" }
                "NS"     { Write-Host "  Name Server: $($result.NameHost)" }
                "CNAME"  { Write-Host "  Alias: $($result.Name), Target: $($result.CName)" }
                "TXT"    { Write-Host "  TXT Record: $($result.Text)" }
                "SOA"    { Write-Host "  Primary Server: $($result.NameHost), Admin: $($result.ResponsiblePerson)" }
                default  { Write-Host "  Record: $($result)" }
            }
        }
    } catch {
        Write-Host "  ❌ No $type records found or query failed." -ForegroundColor Red
    }
    Write-Host ""
}

# -------------------------------
# 2️⃣ WHOIS Info
# -------------------------------
Write-Host "🧾 WHOIS Information" -ForegroundColor Cyan
Write-Host ""

try {
    $whois = Get-WHOIS -DomainName $Domain
    if ($whois) {
        Write-Host "  Registrar: $($whois.Registrar)" -ForegroundColor Green
        Write-Host "  Created On: $($whois.created)" -ForegroundColor Green
        Write-Host "  Expiration Date: $($whois.freedate)" -ForegroundColor Green
    } else {
        Write-Host "  ❌ WHOIS data not available." -ForegroundColor Red
    }
} catch {
    Write-Host "  ❌ WHOIS query failed: $($_.Exception.Message)" -ForegroundColor Red
}

# -------------------------------
# 3️⃣ TLS Info via SslStream
# -------------------------------
Write-Host "`n🔐 TLS Information for ${Domain}:${Port}" -ForegroundColor Cyan
Write-Host ""

try {
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $tcpClient.Connect($Domain, $Port)

    $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, ({ $true }))
    $sslStream.AuthenticateAsClient($Domain)

    Write-Host "✅ TLS Connection Established" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Protocol: $($sslStream.SslProtocol)"
    Write-Host "  Cipher Algorithm: $($sslStream.CipherAlgorithm)"
    Write-Host "  Cipher Strength: $($sslStream.CipherStrength)"
    Write-Host "  Hash Algorithm: $($sslStream.HashAlgorithm)"
    Write-Host "  Hash Strength: $($sslStream.HashStrength)"
    Write-Host "  Key Exchange Algorithm: $($sslStream.KeyExchangeAlgorithm)"
    Write-Host "  Key Exchange Strength: $($sslStream.KeyExchangeStrength)"

    $cert = $sslStream.RemoteCertificate
    $cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $cert

    Write-Host "`n📄 Certificate Info" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Subject: $($cert2.Subject)"
    Write-Host "  Issuer: $($cert2.Issuer)"
    Write-Host "  Valid From: $($cert2.NotBefore)"
    Write-Host "  Valid Until: $($cert2.NotAfter)"
    Write-Host "  Thumbprint: $($cert2.Thumbprint)"
    Write-Host "  Serial Number: $($cert2.SerialNumber)"

    $sslStream.Close()
    $tcpClient.Close()
} catch {
    Write-Host "❌ Failed to connect or retrieve TLS info: $($_.Exception.Message)" -ForegroundColor Red
}