function Invoke-Malformed-DNS
{
    $configures = Get-NetIPConfiguration
    $index = $configures[0].interfaceIndex
    Set-DNSClientServerAddress -interfaceindex $index -ServerAddress ("127.0.0.1")
    $port = 53
    $endpoint = New-Object System.Net.IpEndPoint ([IPAddress]::Any, $port)
    try {
        while($true) {
            $socket = New-Object System.Net.Sockets.UdpClient $port
            $content = $udpclient.Receive([ref]$endpoint)
            $socket.close()
            [Text.Encoding]::ASCII.GetString($content)
        }
    }
    catch {
        Write-Host "$($Error[0])"
    }   
}

function Register-Malformed-Page($PageUrl)
{

}

Invoke-Malformed-DNS