function Get-ShcHtmlEncoded {
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ($null -eq $Text) { return '' }
    $Text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;').Replace("'", '&#39;')
}

function Get-ShcStatusMeta {
    param([Parameter(Mandatory)][string]$Status)
    switch ($Status) {
        'good'     { @{ Color = '#0ca30c'; Icon = [char]0x2714; Label = 'Healthy' } }
        'warning'  { @{ Color = '#c98500'; Icon = [char]0x25B2; Label = 'Needs attention' } }
        'serious'  { @{ Color = '#d9822b'; Icon = [char]0x25B2; Label = 'Degraded' } }
        'critical' { @{ Color = '#d03b3b'; Icon = [char]0x2716; Label = 'Failing' } }
        default    { @{ Color = '#898781'; Icon = [char]0x2013; Label = 'Not measured' } }
    }
}

function Get-ShcGradeMeta {
    param([Parameter(Mandatory)][string]$Grade)
    switch ($Grade) {
        'A' { @{ Color = '#0ca30c'; Label = 'Healthy detection estate' } }
        'B' { @{ Color = '#0ca30c'; Label = 'Sound, with visible wear' } }
        'C' { @{ Color = '#c98500'; Label = 'Rot is setting in' } }
        'D' { @{ Color = '#d9822b'; Label = 'Materially degraded' } }
        default { @{ Color = '#d03b3b'; Label = 'Detection estate is failing' } }
    }
}

function ConvertTo-ShcHtmlTable {
    <#
    .SYNOPSIS
        Renders rows as an HTML table.
    #>
    param(
        [Parameter(Mandatory)][object[]]$Rows,
        [Parameter(Mandatory)][string[]]$Columns,
        [string[]]$Headers
    )
    if (-not $Headers) { $Headers = $Columns }
    $tb = [System.Text.StringBuilder]::new()
    [void]$tb.Append('<div class="table-wrap"><table><thead><tr>')
    foreach ($header in $Headers) { [void]$tb.Append("<th>$(Get-ShcHtmlEncoded $header)</th>") }
    [void]$tb.Append('</tr></thead><tbody>')
    foreach ($row in $Rows) {
        [void]$tb.Append('<tr>')
        foreach ($col in $Columns) {
            $value = $row.$col
            $numeric = $value -is [int] -or $value -is [long] -or $value -is [double] -or $value -is [decimal]
            $cls = if ($numeric) { ' class="num"' } else { '' }
            [void]$tb.Append("<td$cls>$(Get-ShcHtmlEncoded ([string]$value))</td>")
        }
        [void]$tb.Append('</tr>')
    }
    [void]$tb.Append('</tbody></table></div>')
    $tb.ToString()
}

function New-ShcReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Result,
        [Parameter(Mandatory)][string]$Path
    )

    $maxRows = 25
    $gradeMeta = Get-ShcGradeMeta -Grade $Result.Grade
    $scoreText = if ($null -ne $Result.Score) { "$([Math]::Round($Result.Score, 0)) / 100" } else { 'n/a' }

    $kpiTiles = foreach ($kpi in $Result.Kpis) {
        $dot = ''
        if ($kpi.Status -and $kpi.Status -ne 'good') {
            $meta = Get-ShcStatusMeta -Status $kpi.Status
            $dot = "<span class=`"dot`" style=`"background:$($meta.Color)`"></span>"
        }
        "      <div class=`"tile`"><div class=`"tile-value`">$dot$(Get-ShcHtmlEncoded $kpi.Value)</div><div class=`"tile-label`">$(Get-ShcHtmlEncoded $kpi.Label)</div></div>"
    }

    # Volume outliers: two small top-10 tables (noisiest / quietest). Rendered only
    # when the source checks produced data.
    $leaderHtml = ''
    if ($Result.PSObject.Properties['Leaderboards'] -and $Result.Leaderboards) {
        $noisyRows = @($Result.Leaderboards.Noisiest)

        # A leaderboard of ties ranks nothing: suppress it unless at least one
        # rule produced two or more incidents.
        $noisyMax = 0
        foreach ($r in $noisyRows) { if ([long]$r.Incidents -gt $noisyMax) { $noisyMax = [long]$r.Incidents } }
        if ($noisyMax -lt 2) { $noisyRows = @() }

        $boards = @(
            @{
                Title   = 'Noisiest - most incidents'
                Rows    = $noisyRows
                Columns = @('RuleOrIncidentTitle', 'Incidents', 'FalsePositivePct')
                Headers = @('Rule / incident title', 'Incidents', 'FP %')
            }
            @{
                Title   = 'Quietest - fewest alerts'
                Rows    = @($Result.Leaderboards.Quietest)
                Columns = @('RuleName', 'Alerts', 'Severity')
                Headers = @('Rule', 'Alerts', 'Severity')
            }
        )
        $boardCards = foreach ($board in $boards) {
            if ($board.Rows.Count -eq 0) { continue }
            "<section class=`"card`"><div class=`"card-head`"><span class=`"card-title`">$(Get-ShcHtmlEncoded $board.Title)</span></div>" +
            (ConvertTo-ShcHtmlTable -Rows $board.Rows -Columns $board.Columns -Headers $board.Headers) +
            '</section>'
        }
        if (@($boardCards).Count -gt 0) {
            $leaderHtml = "  <h2 class=`"sect`">Volume outliers (top 10)</h2>`n  <div class=`"duo`">`n" +
            (@($boardCards) -join "`n") + "`n  </div>`n"
        }
    }

    # Partition: attention (problems, detailed) vs passing (collapsed) vs not-measured.
    $attention = [System.Text.StringBuilder]::new()
    $passed = [System.Collections.Generic.List[string]]::new()
    $notMeasured = [System.Collections.Generic.List[string]]::new()

    foreach ($check in $Result.Checks) {
        $meta = Get-ShcStatusMeta -Status $check.Status
        $title = Get-ShcHtmlEncoded $check.Title
        $line = Get-ShcHtmlEncoded $check.Headline

        if ($check.Status -eq 'good') {
            $passed.Add("      <li><span class=`"p-ico`" style=`"color:$($meta.Color)`">$($meta.Icon)</span><span class=`"p-title`">$title</span><span class=`"p-note`">$line</span></li>")
            continue
        }
        if ($check.Status -eq 'unknown') {
            $notMeasured.Add("      <li><span class=`"p-ico`" style=`"color:$($meta.Color)`">$($meta.Icon)</span><span class=`"p-title`">$title</span><span class=`"p-note`">$line</span></li>")
            continue
        }

        # Attention card - findings table
        $tableHtml = ''
        $findings = @($check.Findings)
        if ($findings.Count -gt 0 -and $check.Columns.Count -gt 0) {
            $tableHtml = ConvertTo-ShcHtmlTable -Rows @($findings | Select-Object -First $maxRows) -Columns $check.Columns
            if ($findings.Count -gt $maxRows) {
                $tableHtml += "<p class=`"muted`">Showing $maxRows of $($findings.Count) - full list in the JSON output (-PassThru).</p>"
            }
        }

        $summaryHtml = if ($check.Summary) { "<p class=`"summary`">$(Get-ShcHtmlEncoded $check.Summary)</p>" } else { '' }

        [void]$attention.Append(@"
    <section class="card" style="border-left-color:$($meta.Color)">
      <div class="card-head">
        <span class="card-title">$title</span>
        <span class="card-status" style="color:$($meta.Color)">$($meta.Icon) $($meta.Label)</span>
      </div>
      <p class="headline">$line</p>
      $summaryHtml
      $tableHtml
    </section>
"@)
    }

    # Assemble sections
    $body = [System.Text.StringBuilder]::new()
    if ($attention.Length -gt 0) {
        [void]$body.Append("  <h2 class=`"sect`">Needs attention</h2>`n")
        [void]$body.Append($attention.ToString())
    }
    if ($passed.Count -gt 0) {
        [void]$body.Append("  <details class=`"passed-box`" open><summary><span class=`"sect`">Passing</span> <span class=`"count`">$($passed.Count)</span></summary><ul class=`"passed`">`n")
        [void]$body.Append(($passed -join "`n"))
        [void]$body.Append("`n  </ul></details>`n")
    }
    if ($notMeasured.Count -gt 0) {
        [void]$body.Append("  <details class=`"passed-box`"><summary><span class=`"sect`">Not measured</span> <span class=`"count`">$($notMeasured.Count)</span></summary><ul class=`"passed`">`n")
        [void]$body.Append(($notMeasured -join "`n"))
        [void]$body.Append("`n  </ul></details>`n")
    }

    $checksHtml = $body.ToString()
    $kpiHtml = ($kpiTiles -join "`n")

    $template = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sentinel Workspace Health Report - {{WORKSPACE}}</title>
<style>
  :root {
    color-scheme: light dark;
    --page:#f7f8f6; --surface:#ffffff; --ink:#14171a; --ink-2:#565b60;
    --muted:#8b9096; --hairline:#e7e9e6; --border:rgba(20,23,26,0.09);
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --page:#0e1013; --surface:#181b1e; --ink:#f2f4f6; --ink-2:#b6bcc2;
      --muted:#7d8489; --hairline:#282c30; --border:rgba(255,255,255,0.10);
    }
  }
  * { box-sizing:border-box; margin:0; }
  body { background:var(--page); color:var(--ink);
    font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif; padding:32px 16px; }
  .wrap { max-width:860px; margin:0 auto; }
  a { color:inherit; }

  header.hero { display:flex; gap:24px; align-items:center; flex-wrap:wrap;
    background:var(--surface); border:1px solid var(--border); border-radius:14px; padding:26px 28px; }
  .grade { font-size:76px; font-weight:750; line-height:.9; letter-spacing:-2px; }
  .hero-meta h1 { font-size:20px; font-weight:650; }
  .hero-meta .sub { color:var(--ink-2); font-size:13.5px; margin-top:3px; }
  .pill { display:inline-flex; align-items:center; gap:7px; margin-top:11px;
    border-radius:999px; padding:4px 13px; font-size:13.5px; font-weight:550; color:#fff; }

  .tiles { display:grid; grid-template-columns:repeat(auto-fit,minmax(120px,1fr)); gap:9px; margin:16px 0 26px; }
  .tile { background:var(--surface); border:1px solid var(--border); border-radius:11px; padding:13px 15px; }
  .tile-value { font-size:24px; font-weight:680; display:flex; align-items:center; }
  .tile-label { color:var(--ink-2); font-size:12.5px; margin-top:2px; }

  h2.sect, .sect { font-size:13px; font-weight:680; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); }
  h2.sect { margin:22px 2px 10px; }
  .count { font-size:12px; color:var(--muted); font-weight:600; }

  .card { background:var(--surface); border:1px solid var(--border); border-left:4px solid var(--muted);
    border-radius:11px; padding:18px 20px; margin:10px 0; }
  .card-head { display:flex; justify-content:space-between; gap:12px; align-items:baseline; flex-wrap:wrap; }
  .card-title { font-size:16.5px; font-weight:650; }
  .card-status { font-size:13px; font-weight:600; white-space:nowrap; }
  .headline { font-weight:600; margin:9px 0 0; }
  .summary { color:var(--ink-2); font-size:13.5px; margin-top:6px; }
  .dot { display:inline-block; width:9px; height:9px; border-radius:50%; margin-right:8px; flex:none; }

  .table-wrap { overflow-x:auto; margin:13px 0 2px; }
  table { border-collapse:collapse; width:100%; font-size:13px; }
  th { text-align:left; color:var(--muted); font-weight:600; border-bottom:1px solid var(--hairline); padding:6px 12px 6px 0; white-space:nowrap; }
  td { border-bottom:1px solid var(--hairline); padding:6px 12px 6px 0; vertical-align:top; }
  td.num { text-align:right; font-variant-numeric:tabular-nums; }

  .muted { color:var(--muted); font-size:12px; margin-top:6px; }

  .duo { display:grid; grid-template-columns:repeat(auto-fit,minmax(320px,1fr)); gap:10px; }
  .duo .card { margin:0; border-left-color:var(--hairline); }

  .passed-box { background:var(--surface); border:1px solid var(--border); border-radius:11px; padding:14px 20px; margin:10px 0; }
  .passed-box > summary { cursor:pointer; list-style:none; display:flex; gap:8px; align-items:baseline; }
  .passed-box > summary::-webkit-details-marker { display:none; }
  ul.passed { list-style:none; margin:10px 0 2px; }
  ul.passed li { display:grid; grid-template-columns:18px minmax(190px, 250px) 1fr;
    gap:2px 12px; align-items:baseline; padding:8px 0; border-bottom:1px solid var(--hairline); }
  ul.passed li:last-child { border-bottom:none; }
  .p-ico { font-size:12px; font-weight:700; text-align:center; }
  .p-title { font-weight:600; font-size:14px; }
  .p-note { color:var(--ink-2); font-size:13px; }
  @media (max-width:560px) {
    ul.passed li { grid-template-columns:18px 1fr; }
    .p-note { grid-column:2; }
  }

  footer { color:var(--muted); font-size:12px; text-align:center; margin:24px 0 8px; }
</style>
</head>
<body>
<div class="wrap">
  <header class="hero">
    <div class="grade" style="color:{{GRADECOLOR}}">{{GRADE}}</div>
    <div class="hero-meta">
      <h1>Sentinel Workspace Health Report</h1>
      <div class="sub">{{WORKSPACE}} &middot; {{GENERATED}} &middot; {{WINDOW}} &middot; score {{SCORE}}</div>
      <span class="pill" style="background:{{GRADECOLOR}}">{{GRADELABEL}}</span>
    </div>
  </header>

  <div class="tiles">
{{KPITILES}}
  </div>

{{CHECKS}}
{{LEADERBOARDS}}

  <footer>SentinelHealthCheck v{{VERSION}} &middot; read-only &middot; no data leaves your workspace &middot; Purple Shell Security</footer>
</div>
</body>
</html>
'@

    $html = $template.
    Replace('{{WORKSPACE}}', (Get-ShcHtmlEncoded $Result.WorkspaceName)).
    Replace('{{GENERATED}}', (Get-ShcHtmlEncoded $Result.GeneratedUtc)).
    Replace('{{WINDOW}}', (Get-ShcHtmlEncoded $Result.WindowLabel)).
    Replace('{{SCORE}}', (Get-ShcHtmlEncoded $scoreText)).
    Replace('{{GRADE}}', (Get-ShcHtmlEncoded $Result.Grade)).
    Replace('{{GRADECOLOR}}', $gradeMeta.Color).
    Replace('{{GRADELABEL}}', (Get-ShcHtmlEncoded $gradeMeta.Label)).
    Replace('{{KPITILES}}', $kpiHtml).
    Replace('{{LEADERBOARDS}}', $leaderHtml).
    Replace('{{CHECKS}}', $checksHtml).
    Replace('{{VERSION}}', (Get-ShcHtmlEncoded $Result.Version))

    Set-Content -Path $Path -Value $html -Encoding utf8
}
