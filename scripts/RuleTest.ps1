# RuleTest.ps1 - evidence-capture helpers for Phase 3 rule testing
$global:EvidenceRoot = "C:\Lab\Evidence"
$global:HayaExe = "C:\Lab\Hayabusa\hayabusa-3.10.0-win-x64.exe"
$global:HayaRules = "C:\Lab\Hayabusa\rules"
$global:CurrentRule = $null
$global:CurrentRuleDir = $null

function Start-RuleTest {
    param([string]$Id, [string]$Name, [string]$RevertedFrom = "NOT REVERTED")
    $global:CurrentRule = "$Id`_$Name"
    $global:CurrentRuleDir = Join-Path $EvidenceRoot $global:CurrentRule
    New-Item -ItemType Directory -Path $global:CurrentRuleDir -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $global:CurrentRuleDir "screenshots") -Force | Out-Null
    $notes = Join-Path $global:CurrentRuleDir "notes.md"
    "=== Rule test: $global:CurrentRule ===" | Out-File $notes
    "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Add-Content $notes
    "Snapshot reverted to before test: $RevertedFrom" | Add-Content $notes
    Write-Host "`n[Rule test started] $global:CurrentRule" -ForegroundColor Cyan
    Write-Host "Snapshot state: $RevertedFrom" -ForegroundColor Cyan
    Write-Host "Evidence: $global:CurrentRuleDir`n" -ForegroundColor Cyan
}

function Log-Command {
    param([string]$Command, [string]$Label = "command")
    if (-not $global:CurrentRuleDir) { Write-Host "Run Start-RuleTest first" -ForegroundColor Red; return }
    "[$Label] $(Get-Date -Format 'HH:mm:ss')  $Command" | Add-Content (Join-Path $global:CurrentRuleDir "commands.txt")
    Write-Host "Logged: [$Label] $Command" -ForegroundColor DarkGray
}

function Capture-Log {
    param([string]$Phase, [string]$LogName, [int]$MinutesBack = 5)
    if (-not $global:CurrentRuleDir) { Write-Host "Run Start-RuleTest first" -ForegroundColor Red; return }
    $ms = $MinutesBack * 60000
    $evtx = Join-Path $global:CurrentRuleDir "$Phase.evtx"
    $csv  = Join-Path $global:CurrentRuleDir "$Phase`_hayabusa.csv"
    if (Test-Path $evtx) { Remove-Item $evtx -Force }
    $query = "*[System[TimeCreated[timediff(@SystemTime) <= $ms]]]"
    wevtutil epl "$LogName" "$evtx" "/q:$query" /ow:true
    $hayaCmd = "$global:HayaExe csv-timeline -f `"$evtx`" -r $global:HayaRules -o `"$csv`" -w -C -q"
    "[$Phase] $(Get-Date -Format 'HH:mm:ss') HAYABUSA: $hayaCmd" | Add-Content (Join-Path $global:CurrentRuleDir "commands.txt")
    Write-Host "`n--- Hayabusa ($Phase) ---" -ForegroundColor Yellow
    & $global:HayaExe csv-timeline -f $evtx -r $global:HayaRules -o $csv -w -C -q
    $hits = 0
    if (Test-Path $csv) { $hits = (Import-Csv $csv | Measure-Object).Count }
    "[$Phase] log=$LogName  evtx=$Phase.evtx  hayabusa_total_detections=$hits" | Add-Content (Join-Path $global:CurrentRuleDir "notes.md")
    if ($hits -gt 0) { Write-Host "[$Phase] Hayabusa total detections: $hits" -ForegroundColor Green }
    else { Write-Host "[$Phase] Hayabusa detections: 0" -ForegroundColor Magenta }
}

function Test-TargetRule {
    param([string]$Phase, [string]$RuleTitle)
    $csv = Join-Path $global:CurrentRuleDir "$Phase`_hayabusa.csv"
    if (-not (Test-Path $csv)) { Write-Host "No $Phase CSV" -ForegroundColor Red; return }
    $match = Import-Csv $csv | Where-Object { $_.RuleTitle -like "*$RuleTitle*" }
    $notes = Join-Path $global:CurrentRuleDir "notes.md"
    if ($match) {
        $eids = ($match.EventID | Sort-Object -Unique) -join ","
        Write-Host "[$Phase] TARGET RULE FIRED: '$RuleTitle' (EventID: $eids)" -ForegroundColor Green
        "[$Phase] TARGET '$RuleTitle' FIRED (EventID $eids)" | Add-Content $notes
    } else {
        Write-Host "[$Phase] TARGET RULE did NOT fire: '$RuleTitle'" -ForegroundColor Magenta
        "[$Phase] TARGET '$RuleTitle' did NOT fire" | Add-Content $notes
    }
}

function Show-Detections {
    param([string]$Phase)
    $csv = Join-Path $global:CurrentRuleDir "$Phase`_hayabusa.csv"
    if (-not (Test-Path $csv)) { Write-Host "No $Phase CSV" -ForegroundColor Red; return }
    Import-Csv $csv | Select-Object RuleTitle, Level, EventID | Format-Table -AutoSize
}

function Save-Persistence {
    param([string]$VerifyCommand)
    if (-not $global:CurrentRuleDir) { Write-Host "Run Start-RuleTest first" -ForegroundColor Red; return }
    $out = Join-Path $global:CurrentRuleDir "functional_equivalence.txt"
    "# Functional-equivalence proof - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File $out
    "# Command: $VerifyCommand" | Add-Content $out
    "" | Add-Content $out
    (Invoke-Expression $VerifyCommand 2>&1 | Out-String) | Add-Content $out
    "[persistence] verify: $VerifyCommand" | Add-Content (Join-Path $global:CurrentRuleDir "commands.txt")
    Write-Host "Persistence proof saved." -ForegroundColor Cyan
}

function Add-Note {
    param([string]$Text)
    if (-not $global:CurrentRuleDir) { Write-Host "Run Start-RuleTest first" -ForegroundColor Red; return }
    $Text | Add-Content (Join-Path $global:CurrentRuleDir "notes.md")
    Write-Host "Note added." -ForegroundColor DarkGray
}

function Finish-RuleTest {
    Add-Note "Finished: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Host "`n[Rule test finished] $global:CurrentRuleDir" -ForegroundColor Cyan
    Write-Host "Copy to host before reverting:  Copy-Item '$global:CurrentRuleDir' 'Z:\evidence\' -Recurse -Force`n" -ForegroundColor Yellow
    Get-ChildItem $global:CurrentRuleDir -Recurse -File | Select-Object Name, Length | Format-Table -AutoSize
}
