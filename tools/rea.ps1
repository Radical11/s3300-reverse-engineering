# Use the already cached REA package and compatible bundled Node. No setup writes.
$ErrorActionPreference = 'Stop'
$taskNode = 'C:\Users\notak\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe'
$taskRea = 'C:\Users\notak\AppData\Local\npm-cache\_npx\dea9475797100b20\node_modules\rea-agents\scripts\rea.mjs'
if (!(Test-Path -LiteralPath $taskNode) -or !(Test-Path -LiteralPath $taskRea)) {
    throw 'Cached REA or bundled Node has moved. Resolve its location before proceeding.'
}
$taskPreviousPath = $env:PATH
try {
    $env:PATH = "$(Split-Path -Parent $taskNode);$env:PATH"
    & $taskNode $taskRea @args
    exit $LASTEXITCODE
} finally {
    $env:PATH = $taskPreviousPath
}
