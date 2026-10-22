# Build the SAST test fixture zip and POST it to the running backend.
# Writes the response JSON to _sast_fixture/scan_response.json.
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$src  = Join-Path $root 'src'
$zip  = Join-Path $root 'fixture.zip'

# Build zip with Python (stdlib) — escapes the PowerShell-here-string hell.
$py = @"
import os, zipfile
src = r'$src'
zipf = zipfile.ZipFile(r'$zip', 'w', zipfile.ZIP_DEFLATED)
for dp, dn, fn in os.walk(src):
    for f in fn:
        full = os.path.join(dp, f)
        rel  = os.path.relpath(full, src)
        zipf.write(full, os.path.join('src', rel))
zipf.close()
print('zip created')
"@
python -c $py
Get-ChildItem $zip | Select-Object Name, Length

$ProgressPreference = 'SilentlyContinue'
$zip = Join-Path $PSScriptRoot 'fixture.zip'
$respFile = Join-Path $PSScriptRoot 'scan_response.json'

# Use curl.exe (always present on Win10+) because PowerShell 5.1's
# Invoke-WebRequest lacks the `-Form` parameter.
$curlArgs = @(
    '-s', '-X', 'POST',
    'http://localhost:8000/api/scans',
    '-F', "file=@$zip",
    '-o', $respFile,
    '-w', '%{http_code}'
)
$code = & curl.exe @curlArgs
"POST /api/scans -> HTTP $code"
"---"
Get-Content $respFile -Raw

