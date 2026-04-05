# wrapper to run node script with no tricky quoting
$scriptPath = Join-Path $PSScriptRoot '..\scripts\parse_all_js.js'
node $scriptPath
