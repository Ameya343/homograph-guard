# Run homograph-guard inside a locked-down, throw-away container (Docker Desktop on Windows).
#
#   .\sandbox\run.ps1 https://xn--80ak6aa92e.com
#   .\sandbox\run.ps1 --no-dns "pаypal.com"          # no network at all
#   Get-Content urls.txt | .\sandbox\run.ps1 --stdin --json > report.json
#   Get-Content -Raw mail.eml | .\sandbox\run.ps1 --eml -   # every link in an email
#
# Same lock-down as sandbox/run.sh: read-only filesystem, no capabilities, no privilege
# escalation, non-root user, resource limits, and no network when --no-dns is given.
[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(ValueFromPipeline = $true)][AllowEmptyString()][string]$InputLine,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest
)

begin {
$ErrorActionPreference = "Stop"
$piped = [System.Collections.Generic.List[string]]::new()
}
process {
    if ($PSBoundParameters.ContainsKey("InputLine")) { $piped.Add($InputLine) }
}
end {
# Keep Cyrillic/Greek/... characters intact when piping and printing.
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$Image = if ($env:HGUARD_IMAGE) { $env:HGUARD_IMAGE } else { "homograph-guard:latest" }

if ($Rest -contains "--no-dns") {
    $net = @("--network", "none")
} else {
    $net = @("--network", "bridge", "--dns", "127.0.0.1")
}

$flags = @(
    "run", "--rm", "-i",
    "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=8m",
    "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
    "--pids-limit", "64", "--memory", "256m", "--memory-swap", "256m", "--cpus", "1",
    "--user", "10001:10001"
) + $net + @($Image) + $Rest

if ($piped.Count) {
    ($piped -join "`n") | & docker @flags
} else {
    @() | & docker @flags
}
exit $LASTEXITCODE
}
