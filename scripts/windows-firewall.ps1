# Run in an elevated PowerShell prompt on Windows to permit LAN access on TCP 11643 (app)
# and TCP 11644 (proxy origin) without disabling Windows Firewall globally.

Write-Host "Checking existing listeners on ports 11643 and 11644..."
netstat -ano | findstr ":11643 :11644"

foreach ($entry in @(@{Name="Application TCP 11643"; Port=11643}, @{Name="Application Proxy TCP 11644"; Port=11644})) {
  Write-Host "`nAdding scoped inbound firewall rule '$($entry.Name)' for Private network profile..."
  $existing = Get-NetFirewallRule -DisplayName $entry.Name -ErrorAction SilentlyContinue
  if (-not $existing) {
    New-NetFirewallRule `
      -DisplayName $entry.Name `
      -Direction Inbound `
      -Protocol TCP `
      -LocalPort $entry.Port `
      -Action Allow `
      -Profile Private
  } else {
    Write-Host "Rule '$($entry.Name)' already exists."
  }
}

Write-Host "`nTesting loopback ports..."
Test-NetConnection 127.0.0.1 -Port 11643
Test-NetConnection 127.0.0.1 -Port 11644
