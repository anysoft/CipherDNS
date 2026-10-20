param([Parameter(Mandatory = $true, Position = 0)][string]$StateFile)
$ErrorActionPreference = 'Stop'
try {
    $state = Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json
    # Replace this output with your service integration; pass separate arguments.
    # Never use Invoke-Expression with values from the DNS record.
    Write-Output ("Address available: IPv4={0}, IPv6={1}, port={2}" -f $state.ipv4, $state.ipv6, $state.port)
    exit 0
} catch {
    Write-Error 'Hook could not read or apply the local address JSON.'
    exit 1
}
