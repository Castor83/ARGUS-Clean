# Offline regression of the actual baseline unit and the known upstream ordering graph.
# This reads public source only; it never runs shell code, systemd, or a VM.
#requires -Version 7.2
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$argusTemplatePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'templates\argus-vbox-postinstall.sh'
$argusTemplate = Get-Content -LiteralPath $argusTemplatePath -Raw
$argusUnitMatch = [regex]::Matches($argusTemplate, "(?ms)^cat > /etc/systemd/system/argus-baseline\.service <<'ARGUS_UNIT'\r?\n(.*?)^ARGUS_UNIT\r?$")
if ($argusUnitMatch.Count -ne 1) { throw 'Expected exactly one real baseline unit in the public template.' }
$argusBaselineText = $argusUnitMatch[0].Groups[1].Value

# Ordering-relevant directives transcribed after reading the COMPLETE official files:
# https://raw.githubusercontent.com/canonical/cloud-init/26.1/systemd/cloud-final.service
# https://raw.githubusercontent.com/canonical/cloud-init/26.1/systemd/cloud-init.target
# https://raw.githubusercontent.com/systemd/systemd/v255/units/multi-user.target
# Target Wants/Requires -> After rule, including DefaultDependencies exceptions:
# https://raw.githubusercontent.com/systemd/systemd/v255/man/systemd.target.xml
# External nodes are opaque: this proves the known public graph, not all guest units.
$argusCloudFinalText = @'
[Unit]
After=network-online.target time-sync.target cloud-config.service rc-local.service
After=multi-user.target
Before=apt-daily.service
Wants=network-online.target cloud-config.service
[Install]
WantedBy=cloud-init.target
'@
$argusCloudTargetText = @'
[Unit]
After=multi-user.target
'@
$argusMultiUserText = @'
[Unit]
Requires=basic.target
After=basic.target rescue.service rescue.target
'@

function ConvertFrom-ArgusOrderingUnit {
    param([string]$Name, [string]$Text)
    $argusParsed = [pscustomobject]@{Name=$Name;After=@();Before=@();Wants=@();Requires=@();WantedBy=@();DefaultDependencies=$true}
    $argusSection = ''
    foreach ($argusLine in ($Text -split '\r?\n')) {
        if ($argusLine -match '^\[([^]]+)\]$') { $argusSection=$Matches[1]; continue }
        if ($argusLine -match '^(After|Before|Wants|Requires)=(.*)$' -and $argusSection -eq 'Unit') {
            $argusKey=$Matches[1]; $argusValue=$Matches[2]
            $argusParsed.$argusKey += @($argusValue -split '\s+' | Where-Object { $_ })
        } elseif ($argusLine -match '^WantedBy=(.*)$' -and $argusSection -eq 'Install') {
            $argusParsed.WantedBy += @($Matches[1] -split '\s+' | Where-Object { $_ })
        } elseif ($argusLine -match '^DefaultDependencies=(yes|no)$' -and $argusSection -eq 'Unit') {
            $argusParsed.DefaultDependencies = $Matches[1] -eq 'yes'
        }
    }
    return $argusParsed
}
function Get-ArgusOrderingGraph {
    param([string]$BaselineText)
    $argusUnits = @{}
    foreach ($argusUnit in @(
        (ConvertFrom-ArgusOrderingUnit 'argus-baseline.service' $BaselineText),
        (ConvertFrom-ArgusOrderingUnit 'cloud-final.service' $argusCloudFinalText),
        (ConvertFrom-ArgusOrderingUnit 'cloud-init.target' $argusCloudTargetText),
        (ConvertFrom-ArgusOrderingUnit 'multi-user.target' $argusMultiUserText)
    )) { $argusUnits[$argusUnit.Name]=$argusUnit }
    foreach ($argusUnit in @($argusUnits.Values)) {
        foreach ($argusReference in @($argusUnit.After + $argusUnit.Before + $argusUnit.Wants + $argusUnit.Requires + $argusUnit.WantedBy)) {
            if (-not $argusUnits.ContainsKey($argusReference)) { $argusUnits[$argusReference]=ConvertFrom-ArgusOrderingUnit $argusReference '' }
        }
    }
    # Enabling WantedBy=X creates X.wants/service, not a service-side After=X.
    foreach ($argusUnit in @($argusUnits.Values)) {
        foreach ($argusWantedTarget in $argusUnit.WantedBy) { $argusUnits[$argusWantedTarget].Wants += $argusUnit.Name }
    }
    $argusEdges = @{}; $argusInDegree = @{}
    foreach ($argusName in $argusUnits.Keys) { $argusEdges[$argusName]=[Collections.Generic.HashSet[string]]::new(); $argusInDegree[$argusName]=0 }
    foreach ($argusUnit in $argusUnits.Values) {
        foreach ($argusBefore in $argusUnit.After) { $null=$argusEdges[$argusBefore].Add($argusUnit.Name) }
        foreach ($argusAfter in $argusUnit.Before) { $null=$argusEdges[$argusUnit.Name].Add($argusAfter) }
        if ($argusUnit.Name.EndsWith('.target') -and $argusUnit.DefaultDependencies) {
            foreach ($argusDependency in @($argusUnit.Wants + $argusUnit.Requires)) {
                if ($argusUnits[$argusDependency].DefaultDependencies) { $null=$argusEdges[$argusDependency].Add($argusUnit.Name) }
            }
        }
    }
    foreach ($argusName in $argusEdges.Keys) { foreach ($argusAfter in $argusEdges[$argusName]) { $argusInDegree[$argusAfter]++ } }
    $argusReady = [Collections.Generic.Queue[string]]::new()
    foreach ($argusName in @($argusInDegree.Keys | Sort-Object)) { if ($argusInDegree[$argusName] -eq 0) { $argusReady.Enqueue($argusName) } }
    $argusOrder = [Collections.Generic.List[string]]::new()
    while ($argusReady.Count) {
        $argusName = $argusReady.Dequeue(); $argusOrder.Add($argusName)
        foreach ($argusAfter in $argusEdges[$argusName]) { $argusInDegree[$argusAfter]--; if ($argusInDegree[$argusAfter] -eq 0) { $argusReady.Enqueue($argusAfter) } }
    }
    return [pscustomobject]@{
        HasCycle=($argusOrder.Count -ne $argusUnits.Count); Order=$argusOrder.ToArray()
        Blocked=@($argusInDegree.Keys | Where-Object { $argusInDegree[$_] -gt 0 } | Sort-Object)
        Units=$argusUnits; Edges=$argusEdges
    }
}
$argusAssertions = 0
function Assert-ArgusOrdering {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw ('ORDERING REGRESSION: ' + $Message) }
    $script:argusAssertions++
}
$argusCurrent = Get-ArgusOrderingGraph -BaselineText $argusBaselineText
Assert-ArgusOrdering (-not $argusCurrent.HasCycle) ('Current baseline creates an ordering cycle in the known upstream graph: ' + ($argusCurrent.Blocked -join ', '))
Assert-ArgusOrdering (($argusCurrent.Units['argus-baseline.service'].WantedBy -join ' ') -ceq 'cloud-init.target') 'Report must be pulled into cloud-init.target.'
Assert-ArgusOrdering ($argusCurrent.Edges['multi-user.target'].Contains('cloud-final.service') -and $argusCurrent.Edges['cloud-final.service'].Contains('argus-baseline.service') -and $argusCurrent.Edges['argus-baseline.service'].Contains('cloud-init.target')) 'Known ordering must be multi-user -> cloud-final -> report -> cloud-init.target.'
Assert-ArgusOrdering ($argusCurrent.Edges['getty@tty1.service'].Contains('argus-baseline.service')) 'The existing getty ordering must remain.'
Assert-ArgusOrdering $argusCurrent.Units['argus-baseline.service'].DefaultDependencies 'Do not fix the cycle by weakening default service dependencies.'
$argusOldText = $argusBaselineText.Replace('WantedBy=cloud-init.target','WantedBy=multi-user.target')
$argusOld = Get-ArgusOrderingGraph -BaselineText $argusOldText
Assert-ArgusOrdering ($argusOld.HasCycle -and 'argus-baseline.service' -in $argusOld.Blocked -and 'multi-user.target' -in $argusOld.Blocked -and 'cloud-final.service' -in $argusOld.Blocked) 'The old real three-node cycle must be detected.'
$argusWrongAfter = Get-ArgusOrderingGraph -BaselineText ($argusBaselineText.Replace('After=cloud-final.service getty@tty1.service','After=cloud-init.target getty@tty1.service'))
Assert-ArgusOrdering $argusWrongAfter.HasCycle 'Waiting for the containing cloud-init.target would create another cycle and must be detected.'
Write-Output ('PASS: {0} ordering assertions; public known graph only, no guest state or VM execution.' -f $argusAssertions)
