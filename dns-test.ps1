function CheckAdministrator
{
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Invoke-DNS-Change
{
    if((CheckAdministrator) -eq $false) {
        Write-Host "You need to run as Administrator!"
        return
    }
    else {
        Write-Host "Getting your network adapter on computer ..."
        $configuration = Get-NetIPConfiguration
        if ($configuration.length -eq 0) {
            Write-Host "Oh, no! Can't found your network adapter."
        }
        else
        {
            Write-Host "Looking for the primary adapter ..."
            $item = $configuration[0]
            Write-Host "Interface name:" $item.InterfaceDescription

            $dnsIpv4Information = $item.DNSServer[1]
            Write-Host "Dns Address:"
            Write-Host "First  ->" $dnsIpv4Information.ServerAddresses[0]
            Write-Host "Second ->" $dnsIpv4Information.ServerAddresses[1]

            $index = $configuration.interfaceIndex
            Set-DNSClientServerAddress -interfaceindex $index -ServerAddress ("127.0.0.1")
            $answer = Read-Host -Prompt 'Do you want to running the DNS address as default? (Y/N) '
            
            if($answer -ieq "Y") {
                Set-DNSClientServerAddress -interfaceindex $index -ResetServerAddress
                Write-Host "You dns server is change -> 'default'."
            }
            elseif ($answer -ieq "N") {
                Set-DNSClientServerAddress -interfaceindex $index -ServerAddress ("127.0.0.1")
                Write-Host "You dns server is change -> 'localhost', Therefore, Trying turn on the local DNS server ..."
                Start-Process -FilePath "python.exe" -ArgumentList "main.py 0.0.0.0 53" -Wait
                
                Write-Host "Process is terminated, Restarting function ..."
                Invoke-DNS-Change
            }
            else {
                Write-Host "Canceled."
            }
        }
    }
}

Invoke-Dns-Change