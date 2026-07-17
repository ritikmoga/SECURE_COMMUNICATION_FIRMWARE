param(
    [Parameter(Mandatory=$true)]
    [string]$Port
)
$ErrorActionPreference = "Stop"
idf.py -p $Port flash
