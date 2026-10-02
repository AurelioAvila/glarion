$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '../.runtime/release')).Path
foreach($name in @('api.exe','runner.exe','nuclei.exe','local-service.exe','manifest.ps1')){
 $signature=Get-AuthenticodeSignature -LiteralPath (Join-Path $root $name)
 if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne '4F8341A74D16077AE1849DC8B8CAC99F22606754' -or -not $signature.TimeStamperCertificate){throw "Missing valid publisher signature and timestamp: $name"}
}
foreach($component in @('api','runner')){
 $process=Start-Process (Join-Path $root 'local-service.exe') -ArgumentList $component,'--verify' -WindowStyle Hidden -Wait -PassThru
 if($process.ExitCode -ne 0){throw "Valid package rejected: $component"}
}
$file=Join-Path $root 'web/index.html'
$original=[IO.File]::ReadAllBytes($file)
try{
 [IO.File]::AppendAllText($file,'<!-- integrity test -->')
 $process=Start-Process (Join-Path $root 'local-service.exe') -ArgumentList 'api','--verify' -WindowStyle Hidden -Wait -PassThru
 if($process.ExitCode -eq 0){throw 'Modified package was accepted.'}
}finally{[IO.File]::WriteAllBytes($file,$original)}
'Publisher, timestamps, package hashes and tamper rejection verified.'
