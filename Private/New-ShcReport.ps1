function New-ShcReport {
    <#
    .SYNOPSIS
        Renders the scan result as a single, self-contained HTML report card.

    .DESCRIPTION
        The report is one file with no external dependencies: the CSS and a small
        vanilla-JS renderer are inlined, and the scan result is embedded as an
        HTML-safe JSON blob in a <script type="application/json"> island. The
        browser reads that blob and builds the page - score gauge, per-check bar
        chart, severity donut, and searchable / sortable findings tables - so the
        report stays interactive while remaining a local, offline file.

        All "what to show" decisions (row caps, leaderboard suppression, the
        severity roll-up) are made here in PowerShell; the JS is a pure renderer.
        Untrusted strings (rule names, incident titles) ride inside the JSON and
        are neutralized two ways: '<', '>' and '&' are unicode-escaped so nothing
        can break out of the data island, and the renderer writes every value as
        text, never as markup.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Result,
        [Parameter(Mandatory)][string]$Path
    )

    $maxRows = 25

    # Grade -> (status, label). The status name drives the (theme-aware) color in
    # the browser; the hex never leaves the client, so dark mode stays correct.
    $gradeMeta = switch ($Result.Grade) {
        'A' { @{ Status = 'good';     Label = 'Healthy detection estate' } }
        'B' { @{ Status = 'good';     Label = 'Sound, with visible wear' } }
        'C' { @{ Status = 'warning';  Label = 'Rot is setting in' } }
        'D' { @{ Status = 'serious';  Label = 'Materially degraded' } }
        'F' { @{ Status = 'critical'; Label = 'Detection estate is failing' } }
        default { @{ Status = 'unknown'; Label = 'Not enough data to grade' } }
    }
    $scoreValue = if ($null -ne $Result.Score) { [Math]::Round($Result.Score, 0) } else { $null }

    # Nicer column headers than the raw property names; anything not mapped falls
    # back to a CamelCase-split.
    $headerMap = @{
        RuleName            = 'Rule'
        RuleOrIncidentTitle = 'Rule / incident title'
        FalsePositivePct    = 'FP %'
        DaysSilent          = 'Days silent'
        LastSeenUtc         = 'Last data'
        LastModifiedUtc     = 'Last modified'
        LastStatus          = 'State'
        Table               = 'Watched table'
        Detail              = 'Detail'
        Severity            = 'Severity'
        Kind                = 'Kind'
        Incidents           = 'Incidents'
        Alerts              = 'Alerts'
    }

    # Project each check into the shape the renderer consumes. Findings are capped
    # for display; `total` lets the client show "showing N of M".
    $checksOut = foreach ($check in $Result.Checks) {
        $findings = @($check.Findings)
        $cols = @($check.Columns)

        $colMeta = @()
        if ($cols.Count -gt 0) {
            $first = if ($findings.Count -gt 0) { $findings[0] } else { $null }
            $colMeta = foreach ($c in $cols) {
                $isNum = $false
                if ($first -and $first.PSObject.Properties[$c]) {
                    $v = $first.$c
                    $isNum = $v -is [int] -or $v -is [long] -or $v -is [double] -or $v -is [decimal]
                }
                if ($c -match 'Pct$' -or $c -in @('Incidents', 'Alerts', 'DaysSilent')) { $isNum = $true }
                [pscustomobject]@{
                    k   = $c
                    h   = if ($headerMap.ContainsKey($c)) { $headerMap[$c] } else { ($c -creplace '([a-z0-9])([A-Z])', '$1 $2') }
                    num = $isNum
                    sev = ($c -eq 'Severity')
                }
            }
        }

        $rowsOut = @($findings | Select-Object -First $maxRows | ForEach-Object {
                $row = $_
                $o = [ordered]@{}
                foreach ($c in $cols) { $o[$c] = if ($row.PSObject.Properties[$c]) { $row.$c } else { '' } }
                [pscustomobject]$o
            })

        [pscustomobject]@{
            id       = $check.CheckId
            title    = $check.Title
            score    = if ($null -ne $check.Score) { [Math]::Round($check.Score, 0) } else { $null }
            weight   = $check.Weight
            status   = $check.Status
            headline = $check.Headline
            summary  = $check.Summary
            columns  = @($colMeta)
            rows     = $rowsOut
            total    = $findings.Count
        }
    }
    $checksOut = @($checksOut)

    # Severity donut: enabled rules that never fired (HC-04), broken out by
    # severity. Single, always-present source - no cross-check field guessing.
    $severityOut = @()
    $neverFired = $Result.Checks | Where-Object CheckId -eq 'HC-04' | Select-Object -First 1
    if ($neverFired) {
        $order = @('High', 'Medium', 'Low', 'Informational')
        $bySev = [ordered]@{}
        foreach ($f in @($neverFired.Findings)) {
            $s = if ($f.PSObject.Properties['Severity'] -and $f.Severity) { [string]$f.Severity } else { 'Unknown' }
            if (-not $bySev.Contains($s)) { $bySev[$s] = 0 }
            $bySev[$s]++
        }
        $extra = @($bySev.Keys | Where-Object { $_ -notin $order })
        $ranked = @($order | Where-Object { $bySev.Contains($_) }) + $extra
        $severityOut = foreach ($s in $ranked) { [pscustomobject]@{ sev = $s; count = $bySev[$s] } }
        $severityOut = @($severityOut)
    }

    # Volume outliers. Noisiest is suppressed when every rule tied at a single
    # incident - a leaderboard of ties ranks nothing.
    $noisiest = @()
    $quietest = @()
    if ($Result.PSObject.Properties['Leaderboards'] -and $Result.Leaderboards) {
        $noisyRows = @($Result.Leaderboards.Noisiest)
        $noisyMax = 0
        foreach ($r in $noisyRows) { if ([long]$r.Incidents -gt $noisyMax) { $noisyMax = [long]$r.Incidents } }
        if ($noisyMax -ge 2) {
            $noisiest = @($noisyRows | Select-Object -First 10 | ForEach-Object {
                    [pscustomobject]@{
                        RuleOrIncidentTitle = $_.RuleOrIncidentTitle
                        Incidents           = [long]$_.Incidents
                        FalsePositivePct    = $_.FalsePositivePct
                    }
                })
        }
        $quietest = @($Result.Leaderboards.Quietest | Select-Object -First 10 | ForEach-Object {
                [pscustomobject]@{
                    RuleName = $_.RuleName
                    Alerts   = [long]$_.Alerts
                    Severity = $_.Severity
                }
            })
    }

    $kpisOut = @($Result.Kpis | ForEach-Object {
            [pscustomobject]@{ label = $_.Label; value = $_.Value; status = $_.Status }
        })

    $report = [pscustomobject]@{
        workspace   = $Result.WorkspaceName
        generated   = $Result.GeneratedUtc
        window      = $Result.WindowLabel
        version     = $Result.Version
        grade       = $Result.Grade
        gradeStatus = $gradeMeta.Status
        score       = $scoreValue
        verdict     = [pscustomobject]@{ status = $gradeMeta.Status; text = $gradeMeta.Label }
        kpis        = $kpisOut
        checks      = $checksOut
        severity    = @($severityOut)
        noisiest    = @($noisiest)
        quietest    = @($quietest)
    }

    # Embed as an HTML-safe JSON island. Escaping '<' '>' '&' means a rule named
    # "</script>" cannot terminate the block; U+2028/2029 are escaped because they
    # are valid in JSON but break some parsers as raw line separators.
    $json = $report | ConvertTo-Json -Depth 12 -Compress
    $bs = [char]0x5C
    $json = $json.Replace('&', "${bs}u0026")
    $json = $json.Replace('<', "${bs}u003c")
    $json = $json.Replace('>', "${bs}u003e")
    $json = $json.Replace([string][char]0x2028, "${bs}u2028")
    $json = $json.Replace([string][char]0x2029, "${bs}u2029")

    $wsSafe = ([string]$Result.WorkspaceName).Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;')

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
    --page:#f5f5f8; --surface:#ffffff; --surface-2:#faf9fc;
    --ink:#141319; --ink-2:#54525e; --muted:#8a8892;
    --hairline:#e9e8ee; --border:rgba(20,19,25,0.09);
    --accent:#6d4aef; --accent-soft:rgba(109,74,239,0.10);
    --good:#0ca30c; --warning:#e0940a; --serious:#ec835a; --critical:#d03b3b;
    --good-soft:rgba(12,163,12,0.12); --warning-soft:rgba(224,148,10,0.14);
    --serious-soft:rgba(236,131,90,0.14); --critical-soft:rgba(208,59,59,0.12);
    --seq:#3987e5;
    --shadow:0 1px 2px rgba(20,19,25,0.04), 0 4px 16px rgba(20,19,25,0.05);
  }
  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) {
      --page:#0d0d11; --surface:#17171d; --surface-2:#1c1c23;
      --ink:#f2f1f6; --ink-2:#b7b5c2; --muted:#807e8a;
      --hairline:#26262f; --border:rgba(255,255,255,0.10);
      --accent:#9683ff; --accent-soft:rgba(150,131,255,0.14);
      --warning:#fab219; --serious:#ec835a;
      --good-soft:rgba(12,163,12,0.16); --warning-soft:rgba(250,178,25,0.14);
      --serious-soft:rgba(236,131,90,0.16); --critical-soft:rgba(208,59,59,0.18);
      --seq:#5598e7;
      --shadow:0 1px 2px rgba(0,0,0,0.3), 0 4px 20px rgba(0,0,0,0.35);
    }
  }
  :root[data-theme="dark"] {
    --page:#0d0d11; --surface:#17171d; --surface-2:#1c1c23;
    --ink:#f2f1f6; --ink-2:#b7b5c2; --muted:#807e8a;
    --hairline:#26262f; --border:rgba(255,255,255,0.10);
    --accent:#9683ff; --accent-soft:rgba(150,131,255,0.14);
    --warning:#fab219; --serious:#ec835a;
    --good-soft:rgba(12,163,12,0.16); --warning-soft:rgba(250,178,25,0.14);
    --serious-soft:rgba(236,131,90,0.16); --critical-soft:rgba(208,59,59,0.18);
    --seq:#5598e7;
    --shadow:0 1px 2px rgba(0,0,0,0.3), 0 4px 20px rgba(0,0,0,0.35);
  }

  * { box-sizing:border-box; margin:0; }
  html { scroll-behavior:smooth; }
  body { background:var(--page); color:var(--ink);
    font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif;
    -webkit-font-smoothing:antialiased; padding:0 16px 48px; }
  .wrap { max-width:960px; margin:0 auto; }
  a { color:var(--accent); text-decoration:none; }
  [hidden] { display:none !important; }

  .topbar { display:flex; align-items:center; gap:12px; max-width:960px; margin:0 auto; padding:16px 2px 20px; }
  .brand { display:flex; align-items:center; gap:9px; font-weight:680; font-size:14.5px; letter-spacing:-0.01em; }
  .brand .mark { width:22px; height:22px; border-radius:6px; background:var(--accent);
    display:grid; place-items:center; color:#fff; font-size:13px; font-weight:800; }
  .brand .sub { color:var(--muted); font-weight:500; }
  .spacer { flex:1; }
  .toggle { display:inline-flex; align-items:center; gap:7px; cursor:pointer;
    background:var(--surface); border:1px solid var(--border); color:var(--ink-2);
    border-radius:999px; padding:6px 13px; font:inherit; font-size:13px; font-weight:550; }
  .toggle:hover { border-color:var(--accent); color:var(--ink); }
  .toggle:focus-visible { outline:2px solid var(--accent); outline-offset:2px; }
  .toggle svg { width:15px; height:15px; }

  header.hero { display:grid; grid-template-columns:auto 1fr; gap:28px; align-items:center;
    background:var(--surface); border:1px solid var(--border); border-radius:16px;
    padding:26px 30px; box-shadow:var(--shadow); }
  .gauge-wrap { position:relative; width:150px; height:150px; }
  .gauge-wrap .center { position:absolute; inset:0; display:grid; place-items:center; text-align:center; }
  .gauge-grade { font-size:52px; font-weight:760; line-height:1; letter-spacing:-2px; margin-top:14px; }
  .gauge-score { font-size:12.5px; color:var(--ink-2); font-weight:600; margin-top:2px; font-variant-numeric:tabular-nums; }
  .hero-meta h1 { font-size:21px; font-weight:680; letter-spacing:-0.02em; }
  .hero-meta .sub { color:var(--ink-2); font-size:13.5px; margin-top:5px; }
  .hero-meta .sub b { color:var(--ink); font-weight:620; }
  .verdict { display:inline-flex; align-items:center; gap:8px; margin-top:14px;
    border-radius:10px; padding:8px 14px; font-size:13.5px; font-weight:600; }
  .verdict .ico { font-size:14px; }

  h2.sect { font-size:12px; font-weight:700; text-transform:uppercase; letter-spacing:.07em;
    color:var(--muted); margin:30px 4px 12px; display:flex; align-items:baseline; gap:9px; }
  h2.sect .count { font-size:11.5px; color:var(--muted); font-weight:600;
    background:var(--surface-2); border:1px solid var(--border); border-radius:999px; padding:1px 8px; }

  .tiles { display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:11px; }
  .tile { background:var(--surface); border:1px solid var(--border); border-radius:13px; padding:15px 16px; box-shadow:var(--shadow); }
  .tile-value { font-size:27px; font-weight:700; display:flex; align-items:center; gap:8px; letter-spacing:-0.02em; font-variant-numeric:tabular-nums; }
  .tile-label { color:var(--ink-2); font-size:12.5px; margin-top:3px; }
  .tile .dot { width:9px; height:9px; border-radius:50%; flex:none; }

  .charts { display:grid; grid-template-columns:1.35fr 1fr; gap:14px; }
  .charts.solo { grid-template-columns:1fr; }
  @media (max-width:720px){ .charts { grid-template-columns:1fr; } header.hero { grid-template-columns:1fr; justify-items:center; text-align:center; } .hero-meta{ text-align:center; } }
  .card { background:var(--surface); border:1px solid var(--border); border-radius:14px; padding:18px 20px; box-shadow:var(--shadow); }
  .card-head { display:flex; justify-content:space-between; align-items:baseline; gap:12px; margin-bottom:14px; }
  .card-title { font-size:14.5px; font-weight:670; letter-spacing:-0.01em; }
  .card-hint { font-size:12px; color:var(--muted); }

  .bars { display:flex; flex-direction:column; gap:3px; }
  .bar-row { display:grid; grid-template-columns:1fr auto; gap:4px 12px; align-items:center;
    padding:7px 8px; border-radius:9px; cursor:pointer; border:1px solid transparent; }
  .bar-row:hover { background:var(--surface-2); border-color:var(--border); }
  .bar-row:focus-visible { outline:2px solid var(--accent); outline-offset:1px; }
  .bar-label { font-size:13px; font-weight:560; display:flex; align-items:center; gap:8px; }
  .bar-id { font-size:10.5px; font-weight:700; color:var(--muted); font-variant-numeric:tabular-nums;
    background:var(--surface-2); border:1px solid var(--border); border-radius:5px; padding:1px 5px; }
  .bar-score { font-size:13px; font-weight:680; font-variant-numeric:tabular-nums; text-align:right; }
  .bar-track { grid-column:1 / -1; height:8px; border-radius:999px; background:var(--surface-2); overflow:hidden; border:1px solid var(--border); }
  .bar-fill { height:100%; border-radius:999px; transition:width .8s cubic-bezier(.2,.7,.2,1); }

  .donut-wrap { display:flex; align-items:center; gap:18px; }
  .donut-wrap svg { flex:none; }
  .legend { display:flex; flex-direction:column; gap:9px; font-size:13px; flex:1; }
  .legend-row { display:grid; grid-template-columns:auto 1fr auto; gap:9px; align-items:center; }
  .legend .sw { width:11px; height:11px; border-radius:3px; }
  .legend .lv { font-weight:670; font-variant-numeric:tabular-nums; color:var(--ink-2); }

  .check { background:var(--surface); border:1px solid var(--border); border-left:4px solid var(--muted);
    border-radius:14px; padding:20px 22px; margin:12px 0; box-shadow:var(--shadow); scroll-margin-top:16px; }
  .check-head { display:flex; justify-content:space-between; gap:12px; align-items:baseline; flex-wrap:wrap; }
  .check-title { font-size:17px; font-weight:680; letter-spacing:-0.02em; display:flex; align-items:center; gap:10px; }
  .status-pill { display:inline-flex; align-items:center; gap:6px; font-size:12px; font-weight:650; border-radius:999px; padding:3px 11px; white-space:nowrap; }
  .headline { font-weight:600; margin:12px 0 0; font-size:14.5px; }
  .summary { color:var(--ink-2); font-size:13.5px; margin-top:7px; max-width:70ch; }

  .tbl-tools { display:flex; align-items:center; gap:10px; margin:15px 0 6px; flex-wrap:wrap; }
  .search { position:relative; flex:1; min-width:180px; }
  .search input { width:100%; background:var(--surface-2); border:1px solid var(--border); color:var(--ink);
    border-radius:9px; padding:7px 11px 7px 32px; font:inherit; font-size:13px; }
  .search input:focus { outline:2px solid var(--accent-soft); border-color:var(--accent); }
  .search svg { position:absolute; left:10px; top:50%; transform:translateY(-50%); width:14px; height:14px; color:var(--muted); }
  .tbl-count { font-size:12px; color:var(--muted); white-space:nowrap; }
  .table-wrap { overflow-x:auto; margin-top:4px; }
  table { border-collapse:collapse; width:100%; font-size:13px; }
  th { text-align:left; color:var(--muted); font-weight:620; font-size:11.5px; text-transform:uppercase; letter-spacing:.04em;
    border-bottom:1px solid var(--hairline); padding:8px 14px 8px 0; white-space:nowrap; cursor:pointer; user-select:none; }
  th:hover { color:var(--ink-2); }
  th .arrow { opacity:0; font-size:9px; }
  th.sorted .arrow { opacity:1; }
  td { border-bottom:1px solid var(--hairline); padding:8px 14px 8px 0; vertical-align:top; }
  tbody tr:hover td { background:var(--surface-2); }
  td.num { text-align:right; font-variant-numeric:tabular-nums; }
  .sev { display:inline-flex; align-items:center; gap:6px; font-weight:600; font-size:12.5px; }
  .sev .d { width:7px; height:7px; border-radius:50%; }
  .tag { font-size:11.5px; font-weight:600; border-radius:5px; padding:1px 7px; background:var(--surface-2); border:1px solid var(--border); color:var(--ink-2); }
  .muted-note { color:var(--muted); font-size:12px; margin-top:8px; }
  .empty { color:var(--muted); font-size:13px; padding:14px 0; }

  .duo { display:grid; grid-template-columns:1fr 1fr; gap:14px; }
  @media (max-width:640px){ .duo { grid-template-columns:1fr; } }

  details.box { background:var(--surface); border:1px solid var(--border); border-radius:14px; padding:6px 22px; margin:12px 0; box-shadow:var(--shadow); }
  details.box > summary { cursor:pointer; list-style:none; display:flex; align-items:center; gap:10px; padding:14px 0;
    font-size:12px; font-weight:700; text-transform:uppercase; letter-spacing:.07em; color:var(--muted); }
  details.box > summary::-webkit-details-marker { display:none; }
  details.box > summary .chev { transition:transform .2s; margin-left:auto; width:16px; height:16px; color:var(--muted); }
  details.box[open] > summary .chev { transform:rotate(180deg); }
  ul.plain { list-style:none; padding:0 0 12px; }
  ul.plain li { display:grid; grid-template-columns:20px minmax(200px,270px) 1fr; gap:3px 14px; align-items:baseline;
    padding:11px 0; border-top:1px solid var(--hairline); }
  ul.plain .p-ico { font-size:12px; font-weight:800; text-align:center; }
  ul.plain .p-title { font-weight:620; font-size:14px; display:flex; align-items:center; gap:8px; }
  ul.plain .p-note { color:var(--ink-2); font-size:13px; }
  @media (max-width:560px){ ul.plain li { grid-template-columns:20px 1fr; } ul.plain .p-note{ grid-column:2; } }

  footer { color:var(--muted); font-size:12px; text-align:center; margin:34px 0 8px; line-height:1.7; }
  footer .rule { height:1px; background:var(--hairline); margin:0 auto 18px; max-width:200px; }

  #tip { position:fixed; z-index:50; pointer-events:none; opacity:0; transform:translateY(4px);
    transition:opacity .12s, transform .12s; background:var(--ink); color:var(--page);
    font-size:12px; font-weight:550; line-height:1.45; padding:7px 10px; border-radius:8px;
    box-shadow:0 6px 24px rgba(0,0,0,.28); max-width:240px; }
  #tip.on { opacity:1; transform:translateY(0); }
  #tip b { font-weight:720; }

  @media (prefers-reduced-motion: reduce){ * { transition:none !important; } html{ scroll-behavior:auto; } }
</style>
</head>
<body>

<div class="topbar">
  <div class="brand"><span class="mark">S</span>SentinelHealthCheck <span class="sub">&middot; report card</span></div>
  <div class="spacer"></div>
  <button class="toggle" id="themeBtn" aria-label="Toggle light and dark theme">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>
    <span id="themeLabel">Dark</span>
  </button>
</div>

<div class="wrap">

  <header class="hero">
    <div class="gauge-wrap">
      <svg width="150" height="150" viewBox="0 0 150 150" id="gauge" aria-hidden="true"></svg>
      <div class="center">
        <div class="gauge-grade" id="gaugeGrade"></div>
        <div class="gauge-score"><span id="gaugeScore"></span> / 100</div>
      </div>
    </div>
    <div class="hero-meta">
      <h1>Sentinel Workspace Health Report</h1>
      <div class="sub" id="heroSub"></div>
      <div class="verdict" id="verdict"></div>
    </div>
  </header>

  <section id="sec-glance">
    <h2 class="sect">At a glance</h2>
    <div class="tiles" id="tiles"></div>
  </section>

  <section id="sec-charts">
    <h2 class="sect">Health breakdown</h2>
    <div class="charts" id="charts">
      <section class="card">
        <div class="card-head">
          <span class="card-title">Score by check</span>
          <span class="card-hint">worst first &middot; click to jump</span>
        </div>
        <div class="bars" id="bars"></div>
      </section>
      <section class="card" id="donutCard">
        <div class="card-head">
          <span class="card-title">Never-fired rules by severity</span>
          <span class="card-hint">enabled &middot; zero alerts</span>
        </div>
        <div class="donut-wrap">
          <svg width="132" height="132" viewBox="0 0 132 132" id="donut" aria-hidden="true"></svg>
          <div class="legend" id="donutLegend"></div>
        </div>
      </section>
    </div>
  </section>

  <section id="sec-attention">
    <h2 class="sect">Needs attention <span class="count" id="attCount"></span></h2>
    <div id="attention"></div>
  </section>

  <section id="sec-outliers">
    <h2 class="sect">Volume outliers <span class="count">top 10</span></h2>
    <div class="duo">
      <section class="card" id="noisiestCard">
        <div class="card-head"><span class="card-title">Noisiest - most incidents</span></div>
        <div class="table-wrap" id="noisiest"></div>
      </section>
      <section class="card" id="quietestCard">
        <div class="card-head"><span class="card-title">Quietest - fewest alerts</span></div>
        <div class="table-wrap" id="quietest"></div>
      </section>
    </div>
  </section>

  <section id="sec-passing">
    <h2 class="sect">Passing &amp; not measured</h2>
    <div id="passing"></div>
  </section>

  <footer>
    <div class="rule"></div>
    SentinelHealthCheck v<span id="ftVersion"></span> &middot; read-only &middot; nothing leaves your workspace &middot; Purple Shell Security
  </footer>
</div>

<div id="tip" role="status"></div>

<script id="shc-data" type="application/json">{{DATA}}</script>
<script>
"use strict";
const REPORT = JSON.parse(document.getElementById("shc-data").textContent);

const STATUS = {
  good:    { color:"var(--good)",     soft:"var(--good-soft)",     ico:"\u2714", label:"Healthy" },
  warning: { color:"var(--warning)",  soft:"var(--warning-soft)",  ico:"\u25B2", label:"Needs attention" },
  serious: { color:"var(--serious)",  soft:"var(--serious-soft)",  ico:"\u25B2", label:"Degraded" },
  critical:{ color:"var(--critical)", soft:"var(--critical-soft)", ico:"\u2716", label:"Failing" },
  unknown: { color:"var(--muted)",    soft:"var(--surface-2)",     ico:"\u2013", label:"Not measured" },
};
const SEV = { High:"var(--critical)", Medium:"var(--serious)", Low:"var(--warning)", Informational:"var(--seq)" };
const sevColor = s => SEV[s] || "var(--muted)";
const st = k => STATUS[k] || STATUS.unknown;

const $ = (s,r=document)=>r.querySelector(s);
const el = (t,c)=>{ const n=document.createElement(t); if(c) n.className=c; return n; };
const esc = s => String(s).replace(/[&<>"']/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[m]));
const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
const polar = (cx,cy,r,deg)=>{ const a=(deg-90)*Math.PI/180; return [cx+r*Math.cos(a), cy+r*Math.sin(a)]; };
function arc(cx,cy,r,a0,a1){
  const [x0,y0]=polar(cx,cy,r,a0), [x1,y1]=polar(cx,cy,r,a1);
  const large = (a1-a0)%360 > 180 ? 1 : 0;
  return "M "+x0+" "+y0+" A "+r+" "+r+" 0 "+large+" 1 "+x1+" "+y1;
}
function svgEl(name,attrs){ const n=document.createElementNS("http://www.w3.org/2000/svg",name);
  for(const k in attrs) n.setAttribute(k,attrs[k]); return n; }

/* hero: gauge + verdict */
(function(){
  const svg=$("#gauge"), cx=75,cy=75,r=60, start=-135, sweep=270;
  const gs = st(REPORT.gradeStatus).color;
  const has = REPORT.score !== null && REPORT.score !== undefined;
  const frac = has ? Math.max(0,Math.min(100,REPORT.score))/100 : 0;
  svg.appendChild(svgEl("path",{ d:arc(cx,cy,r,start,start+sweep), fill:"none",
    stroke:"var(--hairline)", "stroke-width":11, "stroke-linecap":"round" }));
  if(has){
    const len=2*Math.PI*r*(sweep/360)*frac;
    const val=svgEl("path",{ d:arc(cx,cy,r,start,start+sweep*frac), fill:"none",
      stroke:gs, "stroke-width":11, "stroke-linecap":"round", "stroke-dasharray":(reduce?len:0)+" 9999" });
    if(!reduce) val.style.transition="stroke-dasharray .9s cubic-bezier(.2,.7,.2,1)";
    svg.appendChild(val);
    if(!reduce) requestAnimationFrame(()=>requestAnimationFrame(()=>val.setAttribute("stroke-dasharray",len+" 9999")));
  }
  const g=$("#gaugeGrade"); g.textContent=REPORT.grade; g.style.color=gs;
  $("#gaugeScore").textContent = has ? REPORT.score : "n/a";

  $("#heroSub").innerHTML = "<b>"+esc(REPORT.workspace)+"</b> &middot; "+esc(REPORT.generated)+" &middot; "+esc(REPORT.window);
  $("#ftVersion").textContent = REPORT.version;

  const v=REPORT.verdict, s=st(v.status), n=$("#verdict");
  n.style.background=s.soft; n.style.color=s.color;
  n.innerHTML = '<span class="ico">'+s.ico+'</span><span>'+esc(v.text)+'</span>';
})();

/* KPI tiles */
(function(){
  const wrap=$("#tiles");
  (REPORT.kpis||[]).forEach(k=>{
    const t=el("div","tile");
    const dot = (k.status && k.status!=="good") ? '<span class="dot" style="background:'+st(k.status).color+'"></span>' : "";
    t.innerHTML = '<div class="tile-value">'+dot+esc(k.value)+'</div><div class="tile-label">'+esc(k.label)+'</div>';
    wrap.appendChild(t);
  });
})();

/* per-check bars */
(function(){
  const wrap=$("#bars");
  const rank = c => (c.score===null||c.score===undefined) ? 1e9 : c.score;
  const sorted=[...(REPORT.checks||[])].sort((a,b)=>rank(a)-rank(b));
  sorted.forEach(c=>{
    const s=st(c.status), has=c.score!==null&&c.score!==undefined;
    const row=el("div","bar-row"); row.tabIndex=0; row.setAttribute("role","button");
    row.innerHTML =
      '<div class="bar-label"><span class="bar-id">'+esc(c.id)+'</span>'+esc(c.title)+'</div>'+
      '<div class="bar-score" style="color:'+(has?s.color:"var(--muted)")+'">'+(has?c.score:"\u2013")+'</div>'+
      '<div class="bar-track"><div class="bar-fill" style="background:'+s.color+';width:0"></div></div>';
    const fill=row.querySelector(".bar-fill");
    const w=(has?c.score:0)+"%";
    if(reduce) fill.style.width=w; else requestAnimationFrame(()=>requestAnimationFrame(()=>{ fill.style.width=w; }));
    const go=()=>{ const t=document.getElementById("card-"+c.id); if(t) t.scrollIntoView({block:"center"}); };
    row.addEventListener("click",go);
    row.addEventListener("keydown",e=>{ if(e.key==="Enter"||e.key===" "){ e.preventDefault(); go(); }});
    row.addEventListener("mousemove",e=>tip(e,"<b>"+esc(c.id)+" \u00B7 "+esc(c.title)+"</b><br>"+s.label+" \u00B7 weight "+c.weight+"<br>"+esc(c.headline)));
    row.addEventListener("mouseleave",tipOff);
    wrap.appendChild(row);
  });
})();

/* donut: never-fired by severity */
(function(){
  const data=REPORT.severity||[], total=data.reduce((a,d)=>a+d.count,0);
  if(!data.length || total===0){ $("#donutCard").hidden=true; $("#charts").classList.add("solo"); return; }
  const svg=$("#donut"), leg=$("#donutLegend"), cx=66,cy=66,r=48,w=16, gap=data.length>1?3:0;
  let ang=0;
  data.forEach(d=>{
    const frac=d.count/total, sweep=frac*360;
    const p=svgEl("path",{ d:arc(cx,cy,r,ang+gap/2,ang+sweep-gap/2), fill:"none",
      stroke:sevColor(d.sev), "stroke-width":w, "stroke-linecap":"round" });
    p.addEventListener("mousemove",e=>tip(e,"<b>"+esc(d.sev)+"</b><br>"+d.count+" rules \u00B7 "+Math.round(frac*100)+"%"));
    p.addEventListener("mouseleave",tipOff);
    svg.appendChild(p); ang+=sweep;
    const lr=el("div","legend-row");
    lr.innerHTML='<span class="sw" style="background:'+sevColor(d.sev)+'"></span><span>'+esc(d.sev)+'</span><span class="lv">'+d.count+'</span>';
    leg.appendChild(lr);
  });
  const t1=svgEl("text",{ x:cx, y:cy-3, "text-anchor":"middle", "font-size":26, "font-weight":720, fill:"var(--ink)" });
  t1.textContent=total; svg.appendChild(t1);
  const t2=svgEl("text",{ x:cx, y:cy+15, "text-anchor":"middle", "font-size":10.5, fill:"var(--muted)" });
  t2.textContent="rules"; svg.appendChild(t2);
})();

/* attention cards */
(function(){
  const wrap=$("#attention");
  const att=(REPORT.checks||[]).filter(c=>c.status!=="good"&&c.status!=="unknown");
  if(!att.length){ $("#sec-attention").hidden=true; return; }
  $("#attCount").textContent=att.length;
  const rank = c => (c.score===null||c.score===undefined) ? 1e9 : c.score;
  att.sort((a,b)=>rank(a)-rank(b));
  att.forEach(c=>{
    const s=st(c.status);
    const card=el("section","check"); card.id="card-"+c.id; card.style.borderLeftColor=s.color;
    const scoreTxt = (c.score===null||c.score===undefined) ? "" : " \u00B7 "+c.score+"/100";
    card.innerHTML =
      '<div class="check-head">'+
        '<span class="check-title"><span class="bar-id">'+esc(c.id)+'</span>'+esc(c.title)+'</span>'+
        '<span class="status-pill" style="background:'+s.soft+';color:'+s.color+'">'+s.ico+' '+s.label+scoreTxt+'</span>'+
      '</div>'+
      '<p class="headline">'+esc(c.headline)+'</p>'+
      (c.summary?'<p class="summary">'+esc(c.summary)+'</p>':"");
    if(c.rows&&c.rows.length&&c.columns&&c.columns.length) card.appendChild(buildTable(c));
    wrap.appendChild(card);
  });
})();

function buildTable(c){
  const box=el("div");
  const tools=el("div","tbl-tools");
  const search=el("div","search");
  search.innerHTML='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg><input type="text" placeholder="Filter '+c.rows.length+' findings\u2026" aria-label="Filter findings">';
  const count=el("span","tbl-count");
  tools.append(search,count); box.appendChild(tools);
  const input=search.querySelector("input");

  const tw=el("div","table-wrap"), tbl=el("table"), thead=el("thead"), htr=el("tr");
  c.columns.forEach((col,i)=>{ const th=el("th"); th.innerHTML=esc(col.h)+' <span class="arrow">\u25B2</span>'; th.dataset.i=i; htr.appendChild(th); });
  thead.appendChild(htr); tbl.appendChild(thead);
  const tbody=el("tbody"); tbl.appendChild(tbody); tw.appendChild(tbl); box.appendChild(tw);

  if(c.total>c.rows.length){ const note=el("p","muted-note"); note.textContent="Showing "+c.rows.length+" of "+c.total+" - full list via -PassThru."; box.appendChild(note); }

  let sortCol=-1, sortDir=1;
  function render(){
    const q=input.value.trim().toLowerCase();
    let view=c.rows.filter(r=>!q||c.columns.some(col=>String(r[col.k]).toLowerCase().includes(q)));
    if(sortCol>=0){
      const col=c.columns[sortCol];
      view=view.slice().sort((a,b)=>{
        let x=a[col.k], y=b[col.k];
        if(col.num){ x=parseFloat(x); y=parseFloat(y); if(isNaN(x))x=-Infinity; if(isNaN(y))y=-Infinity; }
        else { x=String(x).toLowerCase(); y=String(y).toLowerCase(); }
        return (x<y?-1:x>y?1:0)*sortDir;
      });
    }
    tbody.innerHTML="";
    if(!view.length){ const tr=el("tr"), td=el("td"); td.colSpan=c.columns.length; td.className="empty";
      td.textContent="No findings match \u201C"+input.value+"\u201D."; tr.appendChild(td); tbody.appendChild(tr); }
    view.forEach(r=>{
      const tr=el("tr");
      c.columns.forEach(col=>{
        const td=el("td"); const val=r[col.k];
        if(col.sev){ td.innerHTML='<span class="sev"><span class="d" style="background:'+sevColor(val)+'"></span>'+esc(val)+'</span>'; }
        else if(col.k==="LastStatus"){ td.innerHTML='<span class="tag">'+esc(val)+'</span>'; }
        else { if(col.num) td.className="num"; td.textContent=val; }
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
    count.textContent=view.length+" of "+c.rows.length;
  }
  input.addEventListener("input",render);
  htr.querySelectorAll("th").forEach(th=>{
    th.addEventListener("click",()=>{
      const i=+th.dataset.i;
      if(sortCol===i) sortDir*=-1; else { sortCol=i; sortDir=1; }
      htr.querySelectorAll("th").forEach(x=>{ x.classList.remove("sorted"); x.querySelector(".arrow").textContent="\u25B2"; });
      th.classList.add("sorted"); th.querySelector(".arrow").textContent=sortDir>0?"\u25B2":"\u25BC";
      render();
    });
  });
  render();
  return box;
}

/* leaderboards */
function simpleTable(target,rows,cols){
  const host=$(target);
  const t=el("table"), thead=el("thead"), htr=el("tr");
  cols.forEach(col=>{ const th=el("th"); th.textContent=col.h; if(col.num) th.style.textAlign="right"; htr.appendChild(th); });
  thead.appendChild(htr); t.appendChild(thead);
  const tb=el("tbody");
  rows.forEach(r=>{
    const tr=el("tr");
    cols.forEach(col=>{
      const td=el("td"), v=r[col.k];
      if(col.sev){ td.innerHTML='<span class="sev"><span class="d" style="background:'+sevColor(v)+'"></span>'+esc(v)+'</span>'; }
      else { if(col.num) td.className="num"; td.textContent=v; }
      tr.appendChild(td);
    });
    tb.appendChild(tr);
  });
  t.appendChild(tb); host.appendChild(t);
}
(function(){
  const noisy=REPORT.noisiest||[], quiet=REPORT.quietest||[];
  if(!noisy.length && !quiet.length){ $("#sec-outliers").hidden=true; return; }
  if(noisy.length) simpleTable("#noisiest",noisy,[{k:"RuleOrIncidentTitle",h:"Rule / incident"},{k:"Incidents",h:"Incidents",num:true},{k:"FalsePositivePct",h:"FP %",num:true}]);
  else $("#noisiestCard").hidden=true;
  if(quiet.length) simpleTable("#quietest",quiet,[{k:"RuleName",h:"Rule"},{k:"Alerts",h:"Alerts",num:true},{k:"Severity",h:"Severity",sev:true}]);
  else $("#quietestCard").hidden=true;
})();

/* passing / not measured */
(function(){
  const wrap=$("#passing");
  const passed=(REPORT.checks||[]).filter(c=>c.status==="good");
  const notm=(REPORT.checks||[]).filter(c=>c.status==="unknown");
  if(!passed.length && !notm.length){ $("#sec-passing").hidden=true; return; }
  function box(title,items,open){
    const chev='<svg class="chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M6 9l6 6 6-6"/></svg>';
    const d=el("details","box"); if(open) d.open=true;
    d.innerHTML='<summary>'+title+' <span class="count">'+items.length+'</span> '+chev+'</summary>';
    const ul=el("ul","plain");
    items.forEach(c=>{
      const s=st(c.status), li=el("li");
      li.innerHTML='<span class="p-ico" style="color:'+s.color+'">'+s.ico+'</span>'+
        '<span class="p-title"><span class="bar-id">'+esc(c.id)+'</span>'+esc(c.title)+'</span>'+
        '<span class="p-note">'+esc(c.headline)+'</span>';
      ul.appendChild(li);
    });
    d.appendChild(ul); wrap.appendChild(d);
  }
  if(passed.length) box("Passing",passed,true);
  if(notm.length) box("Not measured",notm,false);
})();

/* tooltip */
const TIP=$("#tip");
function tip(e,html){ TIP.innerHTML=html; TIP.classList.add("on");
  let x=e.clientX+14, y=e.clientY+14; const w=TIP.offsetWidth, h=TIP.offsetHeight;
  if(x+w>innerWidth-8) x=e.clientX-w-14; if(y+h>innerHeight-8) y=e.clientY-h-14;
  TIP.style.left=x+"px"; TIP.style.top=y+"px";
}
function tipOff(){ TIP.classList.remove("on"); }

/* theme toggle */
(function(){
  const btn=$("#themeBtn"), lbl=$("#themeLabel"), root=document.documentElement;
  const current=()=>root.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches?"dark":"light");
  const apply=t=>{ root.dataset.theme=t; lbl.textContent=t==="dark"?"Light":"Dark"; };
  apply(current());
  btn.addEventListener("click",()=>apply(current()==="dark"?"light":"dark"));
})();
</script>
</body>
</html>
'@

    $html = $template.Replace('{{WORKSPACE}}', $wsSafe).Replace('{{DATA}}', $json)
    Set-Content -Path $Path -Value $html -Encoding utf8
}
