# ===========================================================================
#  Get-NetworkDevices-Pro.ps1  v4.0
#  Erweiterter Netzwerkscanner
#    - Alle Subnetze automatisch (alle aktiven Interfaces)
#    - MAC-Adressen + OUI-Hersteller
#    - VLAN-Erkennung (802.1Q / Hyper-V)
#    - Switch-Port-Info via LLDP + SNMP-Gateway-Query
#    - WMI-Details (OS, Build, Computername, Beschreibung, Domain)
#    - NetBIOS-Namen
#    - SNMP sysDescr / sysName / sysLocation
#    - Port-Scan (Dienste-Erkennung)
#    - Interaktives TUI-Menue (Pfeil-Navigation, Detail-Ansicht)
#    - HTML-Report (dunkel, gruppiert nach Subnetz/VLAN, filterbar)
#    - CSV-Export
#    - Windows und Linux (PowerShell 7)
#    - Offline-/historische Geraete aus ARP/Neighbor, DHCP-Leases und hosts
#    - Status, Quelle, Erkennungsart und letzter bekannter Zeitpunkt
#  Copyright (c) 2026 Giuseppe Groth - Reith IT GmbH
# ===========================================================================

#Requires -Version 5.1
[CmdletBinding()]
param(
    [string[]] $CustomSubnets = @(),
    [int]      $Timeout       = 300,
    [int]      $Threads       = 80,
    [string]   $SNMPCommunity = "public",
    [switch]   $SkipWMI,
    [switch]   $SkipSNMP,
    [switch]   $NoHTML,
    [switch]   $NoExcel,
    [switch]   $SkipPassiveDiscovery,
    [switch]   $IncludeHostsFile,
    [switch]   $SimpleMode,
    [switch]   $NoMenu,
    [switch]   $OpenReport,
    [string[]] $DHCPLeaseFiles = @(),
    [string]   $OutputDirectory = "",
    [string]   $HTMLPath  = "",
    [string]   $CSVPath   = "",
    [string]   $XLSXPath  = ""
)

$script:IsWindows = $PSVersionTable.Platform -eq 'Win32NT' -or $env:OS -eq 'Windows_NT'
$script:IsLinux   = $PSVersionTable.Platform -eq 'Unix' -and (Test-Path '/proc')
$script:Platform  = if ($script:IsWindows) { 'Windows' } elseif ($script:IsLinux) { 'Linux' } else { $PSVersionTable.Platform }
$homeDir = if ($HOME) { $HOME } elseif ($env:USERPROFILE) { $env:USERPROFILE } else { (Get-Location).Path }
if (-not $OutputDirectory) {
    $desk = Join-Path $homeDir 'Desktop'
    $OutputDirectory = if (Test-Path $desk) { $desk } else { $homeDir }
}
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
if (-not $HTMLPath) { $HTMLPath = Join-Path $OutputDirectory "NetworkScan_$stamp.html" }
if (-not $CSVPath)  { $CSVPath  = Join-Path $OutputDirectory "NetworkScan_$stamp.csv" }
if (-not $XLSXPath) { $XLSXPath = Join-Path $OutputDirectory "NetworkScan_$stamp.xlsx" }

# -- SELF-FIX: Zone.Identifier entfernen (OneDrive / Download-Sperre) -------
try { Unblock-File -LiteralPath $MyInvocation.MyCommand.Path -ErrorAction SilentlyContinue } catch {}

# -- SELF-FIX: ExecutionPolicy fuer CurrentUser einmalig auf RemoteSigned ---
# Laeuft nach dem ersten Start via Bypass automatisch, dann nie wieder noetig
if ($script:IsWindows) {
$currentPolicy = Get-ExecutionPolicy -Scope CurrentUser -ErrorAction SilentlyContinue
if ($currentPolicy -notin @('RemoteSigned','Unrestricted','Bypass')) {
    try {
        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force -ErrorAction SilentlyContinue
        Write-Host "  [OK] ExecutionPolicy fuer diesen User auf RemoteSigned gesetzt." -ForegroundColor Green
        Write-Host "       Ab jetzt kann das Script direkt gestartet werden." -ForegroundColor DarkGray
        Write-Host ""
    } catch {}
}
}

Set-StrictMode -Off
$ErrorActionPreference = "SilentlyContinue"

$script:AllDevices = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:Interfaces = @()
$script:VlanMap    = @{}
$script:KnownDevices = [System.Collections.Generic.List[PSCustomObject]]::new()

# -- Konsole-Hilfsfunktion ---------------------------------------------------
function Write-C {
    param([string]$T, [string]$C = "White", [switch]$NL)
    $col = try { [ConsoleColor]$C } catch { [ConsoleColor]::White }
    if ($NL) { Write-Host $T -ForegroundColor $col -NoNewline }
    else      { Write-Host $T -ForegroundColor $col }
}

# -- OUI-Datenbank ----------------------------------------------------------
$OUI = @{
    "000C29"="VMware";"001A11"="Google";"001B63"="Apple";"00215A"="Intel"
    "001E67"="HP Enterprise";"001E8C"="Apple";"002269"="Cisco";"0024E8"="Netgear"
    "002590"="Super Micro";"0026B9"="Dell";"3C970E"="Raspberry Pi"
    "B827EB"="Raspberry Pi";"D83ADD"="Raspberry Pi";"48A9D2"="Ubiquiti"
    "DC9FDB"="Ubiquiti";"E063DA"="Ubiquiti";"F09FC2"="Ubiquiti"
    "24A43C"="AVM FRITZ";"AC9B0A"="AVM";"E4B97A"="AVM";"F4ECF8"="AVM"
    "5C49EB"="HP";"3C52A1"="HP";"1CAB01"="Synology";"001132"="Synology"
    "000142"="Cisco";"0004EA"="Cisco";"00059A"="Cisco";"0007B4"="Cisco"
    "000D29"="Cisco";"000E84"="Cisco";"001201"="Cisco";"001C57"="Cisco"
    "00229A"="Cisco";"000BB4"="Cisco";"0050DA"="Lexmark";"00805F"="Ricoh"
    "0090CC"="Epson";"00409D"="Epson";"00E04C"="Realtek";"3085A9"="Realtek"
    "A0369F"="Realtek";"A8107B"="Realtek";"38F9D3"="Apple";"3C0754"="Apple"
    "8CABEE"="Samsung";"0007AB"="Samsung";"002339"="Samsung";"6CBF1C"="Samsung"
    "000BF9"="Zyxel";"001349"="Zyxel";"00A0C5"="Zyxel";"BC99BC"="Zyxel"
    "00115B"="D-Link";"001195"="D-Link";"1CAFF7"="D-Link"
    "00E018"="TP-Link";"50C7BF"="TP-Link";"6055F9"="TP-Link";"74DA38"="TP-Link"
    "B0BE76"="TP-Link";"C025E9"="TP-Link";"F4F26D"="TP-Link"
    "000022"="Lenovo";"3CE1A1"="Lenovo";"5CF3FC"="Lenovo";"84BE52"="Lenovo"
    "00000E"="Fujitsu";"000BC5"="Fujitsu";"0021B7"="Kyocera";"001E8F"="Kyocera"
    "000001"="Xerox";"0000AA"="Xerox";"00D01E"="Lexmark"
    "B4B024"="MikroTik";"4C5E0C"="MikroTik";"2C3A28"="MikroTik"
    "001D7E"="Cisco-Linksys";"00186E"="Cisco-Linksys"
}

function Get-Vendor([string]$Mac) {
    $clean = ($Mac -replace '[^0-9A-Fa-f]','')
    if ($clean.Length -lt 6) { return "Unbekannt" }
    $oui = $clean.Substring(0,6).ToUpper()
    foreach ($k in $OUI.Keys) { if ($oui -eq $k) { return $OUI[$k] } }
    return "Unbekannt"
}

# -- SNMP v2c Helper ---------------------------------------------------------
function Invoke-SNMPGet([string]$IP, [string]$OIDStr, [string]$Comm = "public", [int]$Ms = 800) {
    if ($SkipSNMP) { return $null }
    try {
        $commB = [System.Text.Encoding]::ASCII.GetBytes($Comm)
        $oidMap = @{
            "1.3.6.1.2.1.1.1.0" = [byte[]](0x2B,0x06,0x01,0x02,0x01,0x01,0x01,0x00)
            "1.3.6.1.2.1.1.5.0" = [byte[]](0x2B,0x06,0x01,0x02,0x01,0x01,0x05,0x00)
            "1.3.6.1.2.1.1.6.0" = [byte[]](0x2B,0x06,0x01,0x02,0x01,0x01,0x06,0x00)
        }
        if (-not $oidMap.ContainsKey($OIDStr)) { return $null }
        $ob = $oidMap[$OIDStr]
        # VarBind: SEQUENCE { OID, Null }
        $vb  = [byte[]](0x30,($ob.Count+4),0x06,$ob.Count) + $ob + [byte[]](0x05,0x00)
        # VarBindList: SEQUENCE { VarBind }
        $vbl = [byte[]](0x30,$vb.Count) + $vb
        # PDU: GetRequest { reqId, errStatus, errIndex, vbl }
        $pduContent = [byte[]](0x02,0x04,0x00,0x00,0x00,0x01,0x02,0x01,0x00,0x02,0x01,0x00) + $vbl
        $pdu = [byte[]](0xA0,$pduContent.Count) + $pduContent
        # Message: SEQUENCE { version=1, community, pdu }
        $msgContent = [byte[]](0x02,0x01,0x01,0x04,$commB.Count) + $commB + $pdu
        $msg = [byte[]](0x30,$msgContent.Count) + $msgContent
        $udp = [System.Net.Sockets.UdpClient]::new()
        $udp.Client.ReceiveTimeout = $Ms
        $ep  = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse($IP),161)
        [void]$udp.Send($msg,$msg.Length,$ep)
        $rep = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any,0)
        $r   = $udp.Receive([ref]$rep) ; $udp.Close()
        # Parse: find OCTET STRING (0x04) values, skip community
        for ($i=0; $i -lt ($r.Length-2); $i++) {
            if ($r[$i] -eq 0x04) {
                $len = [int]$r[$i+1] ; $off = 2
                if ($r[$i+1] -ge 0x81) { $nb=$r[$i+1]-band 0x7F ; $len=0 ; for($j=0;$j-lt$nb;$j++){$len=($len-shl 8)-bor[int]$r[$i+2+$j]} ; $off=2+$nb }
                if ($len -gt 3 -and $len -lt 400 -and ($i+$off+$len) -le $r.Length) {
                    $s = [System.Text.Encoding]::ASCII.GetString($r,$i+$off,$len).Trim()
                    if ($s -ne $Comm -and $s -match '^[\x20-\x7E]+') { return $s }
                }
            }
        }
    } catch {}
    return $null
}

# -- Netzwerk-Interface-Erkennung --------------------------------------------
function Convert-PrefixToSubnet([string]$IP, [int]$Prefix) {
    $b = [System.Net.IPAddress]::Parse($IP).GetAddressBytes()
    $mask = [uint32]0
    if ($Prefix -gt 0) { $mask = [uint32]::MaxValue -shl (32-$Prefix) }
    [Array]::Reverse($b); $n = [BitConverter]::ToUInt32($b,0) -band $mask
    $nb=[BitConverter]::GetBytes($n); [Array]::Reverse($nb)
    return ([System.Net.IPAddress]::new($nb)).ToString()
}

function Get-LocalInterfaces {
    $result = @()
    if ($script:IsWindows) {
        $addrs = Get-NetIPAddress -AddressFamily IPv4 -EA SilentlyContinue | Where-Object {
            $_.IPAddress -notmatch '^127\.|^169\.254\.' -and $_.PrefixLength -ge 8 -and $_.PrefixLength -le 30
        }
        foreach ($a in $addrs) {
            $adp=Get-NetAdapter -InterfaceIndex $a.InterfaceIndex -EA SilentlyContinue
            if (-not $adp -or $adp.Status -ne 'Up') { continue }
            $vlan=0
            $vp=Get-NetAdapterAdvancedProperty -Name $adp.Name -EA SilentlyContinue | Where-Object {$_.RegistryKeyword -match 'VlanID|VLAN_ID|VlanTag'} | Select-Object -First 1
            if($vp){try{$vlan=[int]$vp.RegistryValue}catch{}}
            $gw=(Get-NetRoute -InterfaceIndex $a.InterfaceIndex -DestinationPrefix '0.0.0.0/0' -EA SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1).NextHop
            $lp=Get-NetAdapterLldpProperties -Name $adp.Name -EA SilentlyContinue
            $net=Convert-PrefixToSubnet $a.IPAddress $a.PrefixLength
            $sn=($net -split '\.')[0..2] -join '.'
            $result += [PSCustomObject]@{AdapterName=$adp.Name;Description=$adp.InterfaceDescription;MacAddress=$adp.MacAddress;IPAddress=$a.IPAddress;PrefixLength=$a.PrefixLength;Network=$net;Subnet=$sn;Gateway=if($gw){$gw}else{'-'};VlanID=$vlan;LinkSpeed=$adp.LinkSpeed;LldpTx=if($lp){$lp.TransmitEnabled}else{$false};LldpRx=if($lp){$lp.ReceiveEnabled}else{$false}}
            if($vlan -gt 0){$script:VlanMap[$sn]=$vlan}
        }
    } else {
        $routes = @(& ip -4 route 2>$null)
        $defaultGw = (($routes | Where-Object {$_ -match '^default via\s+(\S+)'} | Select-Object -First 1) -replace '^default via\s+(\S+).*$','$1')
        foreach($line in @(& ip -o -4 addr show up 2>$null)) {
            if($line -notmatch '^\d+:\s+([^\s]+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)'){continue}
            $name=$Matches[1];$ip=$Matches[2];$prefix=[int]$Matches[3]
            if($ip -match '^127\.|^169\.254\.' -or $prefix -lt 8 -or $prefix -gt 30){continue}
            $link=& ip -o link show dev $name 2>$null | Select-Object -First 1
            $mac='-'; if($link -match 'link/ether\s+([0-9a-f:]{17})'){$mac=$Matches[1].ToUpper()}
            $vlan=0; $detail=& ip -d link show dev $name 2>$null | Out-String; if($detail -match 'vlan protocol \S+ id (\d+)'){$vlan=[int]$Matches[1]}
            $net=Convert-PrefixToSubnet $ip $prefix; $sn=($net -split '\.')[0..2] -join '.'
            $gwLine=$routes | Where-Object {$_ -match ('dev\s+'+[regex]::Escape($name)+'(?:\s|$)') -and $_ -match '^default via'} | Select-Object -First 1
            $gw=if($gwLine -match '^default via\s+(\S+)'){$Matches[1]}elseif($defaultGw){$defaultGw}else{'-'}
            $speed='-'; if(Test-Path "/sys/class/net/$name/speed"){try{$speed="$(Get-Content "/sys/class/net/$name/speed") Mbps"}catch{}}
            $result += [PSCustomObject]@{AdapterName=$name;Description='Linux network interface';MacAddress=$mac;IPAddress=$ip;PrefixLength=$prefix;Network=$net;Subnet=$sn;Gateway=$gw;VlanID=$vlan;LinkSpeed=$speed;LldpTx=$false;LldpRx=$false}
            if($vlan -gt 0){$script:VlanMap[$sn]=$vlan}
        }
    }
    return $result
}

# -- Automatische Subnetz-Erkennung ------------------------------------------
# Findet ALLE erreichbaren Subnetze, nicht nur direkt verbundene:
# 1. Lokale Interfaces
# 2. Windows-Routing-Tabelle (statische + dynamische Routen)
# 3. Neighbor-Cache / ARP-Cache (kuerzlich kommunizierte Hosts)
# 4. Wenn /16 oder breiter: Gateway-Probe aller /24-Subnetze via RunspacePool
function Find-AllSubnets([PSCustomObject[]]$LocalIfaces) {
    Write-C "  [*] Subnetz-Erkennung laeuft ..." DarkCyan
    $found = [System.Collections.Generic.HashSet[string]]::new()

    function Add-Subnet([string]$sn) {
        if ($sn -match '^\d+\.\d+\.\d+$' -and
            $sn -notmatch "^(127|169\.254|224|240|255)") {
            [void]$found.Add($sn)
        }
    }

    # 1. Lokale Interfaces
    foreach ($ifc in $LocalIfaces) { Add-Subnet $ifc.Subnet }

    # 2. Routing-Tabelle (alle bekannten Routen inkl. statische)
    if ($script:IsWindows) { Get-NetRoute -AddressFamily IPv4 -EA SilentlyContinue | Where-Object {
        $_.PrefixLength -ge 8 -and $_.PrefixLength -le 30 -and
        $_.DestinationPrefix -notmatch "^(0\.0\.0\.0|127\.|169\.254\.|224\.|240\.|255\.)"
    } | ForEach-Object {
        $net = ($_.DestinationPrefix -split '/')[0]
        if ($net -match '^(\d+)\.(\d+)\.(\d+)\.') { Add-Subnet ("{0}.{1}.{2}" -f $Matches[1],$Matches[2],$Matches[3]) }
    } } else {
        & ip -4 route 2>$null | ForEach-Object { if($_ -match '^(\d+)\.(\d+)\.(\d+)\.\d+/(\d+)'){ Add-Subnet ("{0}.{1}.{2}" -f $Matches[1],$Matches[2],$Matches[3]) } }
    }

    # 3. Neighbor-Cache (modernes ARP - kennt alle kuerzlich kommunizierten Hosts)
    if ($script:IsWindows) {
        Get-NetNeighbor -AddressFamily IPv4 -EA SilentlyContinue | Where-Object {$_.State -notin @('Unreachable','Incomplete') -and $_.IPAddress -notmatch '^(127\.|169\.254\.|224\.|255\.)'} | ForEach-Object {if($_.IPAddress -match '^(\d+)\.(\d+)\.(\d+)\.'){Add-Subnet ("{0}.{1}.{2}" -f $Matches[1],$Matches[2],$Matches[3])}}
        arp -a 2>$null | ForEach-Object {if($_ -match '^\s+(\d+)\.(\d+)\.(\d+)\.\d+'){Add-Subnet ("{0}.{1}.{2}" -f $Matches[1],$Matches[2],$Matches[3])}}
    } else {
        & ip -4 neigh show 2>$null | ForEach-Object {if($_ -match '^(\d+)\.(\d+)\.(\d+)\.\d+'){Add-Subnet ("{0}.{1}.{2}" -f $Matches[1],$Matches[2],$Matches[3])}}
    }

    # 4. Breite Netze (/16 oder weiter): alle /24-Gateways proben
    foreach ($ifc in $LocalIfaces) {
        if ($ifc.PrefixLength -gt 16) { continue }  # nur bei /16 oder breiter
        $pts = $ifc.IPAddress.Split('.')
        $base = "{0}.{1}" -f $pts[0],$pts[1]
        Write-C ("  [*] Breites Netz erkannt ({0}.x.x/{1}) - probe 255 Gateway-IPs ..." -f $base,$ifc.PrefixLength) Yellow

        $pool2 = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, 128)
        $pool2.Open()
        $probes = [System.Collections.Generic.List[hashtable]]::new()
        $sbP = { param($ip,$to) $p=New-Object System.Net.NetworkInformation.Ping ; try{if(($p.Send($ip,$to)).Status-eq'Success'){$ip}}catch{} }

        for ($j = 0; $j -le 254; $j++) {
            $gwIP = "{0}.{1}.1" -f $base,$j
            $ps2  = [System.Management.Automation.PowerShell]::Create()
            $ps2.RunspacePool = $pool2
            [void]$ps2.AddScript($sbP).AddArgument($gwIP).AddArgument(300)
            $probes.Add(@{ PS=$ps2; H=$ps2.BeginInvoke(); SN=("{0}.{1}" -f $base,$j) })
        }
        $doneP = 0
        while ($probes.Count -gt 0) {
            for ($pi=$probes.Count-1; $pi-ge 0; $pi--) {
                if ($probes[$pi].H.IsCompleted) {
                    $r2 = $probes[$pi].PS.EndInvoke($probes[$pi].H)
                    if ($r2) { Add-Subnet $probes[$pi].SN ; Write-C ("    gefunden: {0}.x" -f $probes[$pi].SN) Green }
                    $probes[$pi].PS.Dispose() ; $probes.RemoveAt($pi) ; $doneP++
                }
            }
            if ($probes.Count -gt 0) {
                Write-Progress -Activity "Gateway-Probe" -Status ("{0}/255 geprueft" -f $doneP) -PercentComplete ([int]($doneP*100/255))
                Start-Sleep -Milliseconds 60
            }
        }
        Write-Progress -Activity "Gateway-Probe" -Completed
        $pool2.Close() ; $pool2.Dispose()
    }

    # Sortiert ausgeben
    $sorted = $found | Sort-Object {
        $p = $_.Split('.') ; [int]$p[0]*65536 + [int]$p[1]*256 + [int]$p[2]
    }
    Write-C ("  [*] {0} Subnetze erkannt: {1}" -f @($sorted).Count,($sorted -join "  |  ")) DarkCyan
    return @($sorted)
}
function Get-MacFromARP([string]$IP) {
    if ($script:IsWindows) {
        $n=Get-NetNeighbor -IPAddress $IP -EA SilentlyContinue | Where-Object {$_.LinkLayerAddress -match '([0-9A-Fa-f]{2}[-:]){5}'} | Select-Object -First 1
        if($n){return $n.LinkLayerAddress.ToUpper()}
        $a=arp -a $IP 2>$null | Select-String ([regex]::Escape($IP)); if($a){$m=[regex]::Match($a.ToString(),'([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}');if($m.Success){return $m.Value.ToUpper()}}
    } else {
        $a=& ip neigh show $IP 2>$null | Select-Object -First 1; if($a -match 'lladdr\s+([0-9a-f:]{17})'){return $Matches[1].ToUpper()}
    }
    return '-'
}

function Get-NetBIOSName([string]$IP) {
    if(-not $script:IsWindows){return '-'}
    $nb=nbtstat -A $IP 2>$null; if($nb){$l=$nb|Select-String '<00>.*UNIQUE'|Select-Object -First 1;if($l){return (($l-replace '^\s+','').Split(' ')[0]).ToUpper()}}
    return '-'
}

function Get-WMIDetails([string]$IP) {
    $r=@{OS='';Build='';CompName='';Domain='';Desc='';Workgroup=''}
    if($SkipWMI -or -not $script:IsWindows){return $r}
    try {
        if(Get-Command Get-CimInstance -EA SilentlyContinue){$cs=Get-CimInstance Win32_ComputerSystem -ComputerName $IP -EA Stop;$os=Get-CimInstance Win32_OperatingSystem -ComputerName $IP -EA Stop}else{$cs=Get-WmiObject Win32_ComputerSystem -ComputerName $IP -EA Stop;$os=Get-WmiObject Win32_OperatingSystem -ComputerName $IP -EA Stop}
        $r.CompName=$cs.Name;$r.Domain=$cs.Domain;$r.Workgroup=if($cs.Workgroup){$cs.Workgroup}else{$cs.Domain};$r.Desc=$cs.Description;$r.OS=$os.Caption-replace 'Microsoft ','';$r.Build=$os.BuildNumber
    }catch{}
    return $r
}

function Get-OpenPorts([string]$IP) {
    $portMap = @{21="FTP";22="SSH";23="Telnet";25="SMTP";53="DNS";80="HTTP";
                 110="POP3";135="RPC";139="NetBIOS";143="IMAP";443="HTTPS";
                 445="SMB";631="Drucker(IPP)";3389="RDP";5985="WinRM";
                 8080="HTTP-Alt";8443="HTTPS-Alt";9100="RAW-Druck"}
    $open = @()
    foreach ($p in $portMap.Keys | Sort-Object) {
        try {
            $t = [System.Net.Sockets.TcpClient]::new()
            $x = $t.BeginConnect($IP,$p,$null,$null)
            if ($x.AsyncWaitHandle.WaitOne(150,$false) -and $t.Connected) { $open += "{0}/{1}" -f $p,$portMap[$p] }
            $t.Close()
        } catch {}
    }
    return ($open -join "  ")
}

function Get-DeviceType([PSCustomObject]$d) {
    $os=$d.WMI_OS ; $sn=$d.SNMP_Descr ; $h=$d.Hostname ; $v=$d.Vendor ; $p=$d.OpenPorts
    if ($os -match "Windows 11")     { return "Windows 11 PC" }
    if ($os -match "Windows 10")     { return "Windows 10 PC" }
    if ($os -match "Windows Server") { return "Windows Server" }
    if ($os -match "Windows 7|Windows 8") { return "Windows PC (Legacy)" }
    if ($sn -match "Linux|Ubuntu|Debian|CentOS|RHEL") { return "Linux" }
    if ($sn -match "Cisco IOS|IOS-XE|NX-OS") { return "Cisco" }
    if ($sn -match "Juniper|JUNOS")   { return "Juniper" }
    if ($sn -match "RouterOS|MikroTik") { return "MikroTik" }
    if ($sn -match "UniFi|Ubiquiti")  { return "Ubiquiti/UniFi" }
    if ($sn -match "FRITZ|AVM")       { return "AVM FRITZ!Box" }
    if ($v  -match "AVM")             { return "AVM FRITZ!Box" }
    if ($v  -match "^Cisco")          { return "Cisco" }
    if ($v  -match "Ubiquiti")        { return "Ubiquiti/UniFi" }
    if ($v  -match "MikroTik")        { return "MikroTik" }
    if ($v  -match "Synology")        { return "Synology NAS" }
    if ($p  -match "631|9100")        { return "Drucker" }
    if ($v  -match "HP|Ricoh|Epson|Lexmark|Kyocera|Xerox") { return "Drucker" }
    if ($p  -match "3389" -and $p -match "445") { return "Windows PC" }
    if ($p  -match "22"   -and $p -notmatch "445") { return "Linux/Unix" }
    if ($h  -match "router|gw\.|gateway") { return "Router" }
    if ($h  -match "sw\.|switch")         { return "Switch" }
    if ($h  -match "printer|drucker|mfp") { return "Drucker" }
    if ($h  -match "cam\.|kamera|camera") { return "IP-Kamera" }
    if ($h  -match "ap\.|wlan|wifi")      { return "Access Point" }
    if ($h  -match "nas\.|storage")       { return "NAS" }
    return "Unbekannt"
}

$ICONS = @{
    "Windows 11 PC"="[W11]";"Windows 10 PC"="[W10]";"Windows Server"="[SRV]"
    "Windows PC (Legacy)"="[WXP]";"Windows PC"="[WIN]";"Linux/Unix"="[LNX]"
    "Linux"="[LNX]";"Cisco"="[CSC]";"Juniper"="[JNP]";"MikroTik"="[MTK]"
    "Ubiquiti/UniFi"="[UFI]";"AVM FRITZ!Box"="[FBX]";"Drucker"="[PRN]"
    "IP-Kamera"="[CAM]";"Access Point"="[ AP]";"Synology NAS"="[NAS]"
    "NAS"="[NAS]";"Router"="[RTR]";"Switch"="[SWT]";"Unbekannt"="[ ? ]"
}

$DCOLORS = @{
    "Windows 11 PC"="Cyan";"Windows 10 PC"="Cyan";"Windows Server"="Green"
    "Windows PC (Legacy)"="DarkCyan";"Windows PC"="Cyan";"Linux/Unix"="Yellow"
    "Linux"="Yellow";"Cisco"="Magenta";"Juniper"="Magenta";"MikroTik"="Magenta"
    "Ubiquiti/UniFi"="DarkMagenta";"AVM FRITZ!Box"="DarkMagenta"
    "Drucker"="DarkYellow";"IP-Kamera"="DarkCyan";"Access Point"="DarkCyan"
    "Synology NAS"="DarkGreen";"NAS"="DarkGreen";"Router"="Magenta"
    "Switch"="Magenta";"Unbekannt"="DarkGray"
}

# -- Passive / historische Erkennung -----------------------------------------
function Add-KnownDevice([string]$IP,[string]$MAC='-',[string]$Name='-',[string]$Source='Unbekannt',[string]$LastSeen='') {
    if($IP -notmatch '^\d{1,3}(\.\d{1,3}){3}$' -or $IP -match '^(127\.|169\.254\.|224\.|255\.)'){return}
    $existing=$script:KnownDevices|Where-Object{$_.IP -eq $IP}|Select-Object -First 1
    if($existing){if($existing.MAC -eq '-' -and $MAC -ne '-'){$existing.MAC=$MAC};if($existing.Name -eq '-' -and $Name -ne '-'){$existing.Name=$Name};if($existing.Source -notmatch [regex]::Escape($Source)){$existing.Source+="; $Source"};return}
    $script:KnownDevices.Add([PSCustomObject]@{IP=$IP;MAC=if($MAC){$MAC.ToUpper()}else{'-'};Name=if($Name){$Name}else{'-'};Source=$Source;LastSeen=$LastSeen})
}
function Get-PassiveKnownDevices {
    if($SkipPassiveDiscovery){return @()}
    Write-C '  [*] Passive Quellen: Neighbor/ARP, DHCP-Leases und optional hosts ...' DarkCyan
    if($script:IsWindows){
        Get-NetNeighbor -AddressFamily IPv4 -EA SilentlyContinue|Where-Object{$_.IPAddress -and $_.State -ne 'Incomplete'}|ForEach-Object{Add-KnownDevice $_.IPAddress $_.LinkLayerAddress '-' ("Windows Neighbor ({0})" -f $_.State) ''}
        arp -a 2>$null|ForEach-Object{if($_ -match '^\s+(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f-]{17})'){Add-KnownDevice $Matches[1] $Matches[2] '-' 'ARP-Cache' ''}}
    }else{
        & ip -4 neigh show 2>$null|ForEach-Object{if($_ -match '^(\d+\.\d+\.\d+\.\d+).*?lladdr\s+([0-9a-f:]{17}).*?\s(\w+)$'){Add-KnownDevice $Matches[1] $Matches[2] '-' ("Linux Neighbor ({0})" -f $Matches[3]) ''}}
    }
    $leaseCandidates=@($DHCPLeaseFiles)
    if($script:IsLinux){$leaseCandidates += @('/var/lib/misc/dnsmasq.leases','/var/lib/dhcp/dhcpd.leases','/var/lib/NetworkManager/dnsmasq-*','/var/lib/NetworkManager/internal-*')}
    foreach($pat in ($leaseCandidates|Select-Object -Unique)){
        foreach($file in @(Get-Item $pat -EA SilentlyContinue)){
            $lines=Get-Content $file.FullName -EA SilentlyContinue
            foreach($l in $lines){
                if($l -match '^(\d{9,})\s+([0-9a-f:]{17})\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)'){$when='';try{$when=[DateTimeOffset]::FromUnixTimeSeconds([int64]$Matches[1]).LocalDateTime.ToString('yyyy-MM-dd HH:mm:ss')}catch{};Add-KnownDevice $Matches[3] $Matches[2] $Matches[4] ("DHCP-Lease: {0}" -f $file.Name) $when}
                elseif($l -match '^\s*fixed-address\s+(\d+\.\d+\.\d+\.\d+);'){Add-KnownDevice $Matches[1] '-' '-' ("DHCP-Konfiguration: {0}" -f $file.Name) ''}
            }
        }
    }
    if($IncludeHostsFile){$hf=if($script:IsWindows){Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'}else{'/etc/hosts'};Get-Content $hf -EA SilentlyContinue|ForEach-Object{if($_ -match '^\s*(\d+\.\d+\.\d+\.\d+)\s+([^#\s]+)' -and $Matches[1] -notmatch '^127\.'){Add-KnownDevice $Matches[1] '-' $Matches[2] 'hosts-Datei' ''}}}
    Write-C ("    => {0} bekannte Eintraege aus passiven Quellen" -f $script:KnownDevices.Count) Green
    return @($script:KnownDevices)
}

# -- Ping Sweep (Runspace-Pool, kein Start-Job) ------------------------------
# Start-Job erstellt pro IP einen eigenen PS-Prozess -> haengt sich bei ~80 auf
# RunspacePool nutzt echte Threads im selben Prozess -> kein Einfrieren
function Start-PingSweep([string[]]$Subnets) {
    $total = $Subnets.Count * 254
    Write-C ("[1/3] Ping-Sweep: {0} Subnetze, {1} IPs, max. {2} parallele Threads" -f $Subnets.Count,$total,$Threads) Cyan

    $alive = [System.Collections.Concurrent.ConcurrentBag[object]]::new()

    # RunspacePool: max $Threads gleichzeitige Threads, kein Prozess-Overhead
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $Threads)
    $pool.Open()

    $sb = {
        param($ip, $to)
        $p = New-Object System.Net.NetworkInformation.Ping
        try { if (($p.Send($ip, $to)).Status -eq 'Success') { return [PSCustomObject]@{IP=$ip;Method='ICMP'} } } catch {}
        foreach($port in @(443,80,22,445,3389,9100)){try{$t=[System.Net.Sockets.TcpClient]::new();$h=$t.BeginConnect($ip,$port,$null,$null);if($h.AsyncWaitHandle.WaitOne([Math]::Min($to,180),$false)-and$t.Connected){$t.Close();return [PSCustomObject]@{IP=$ip;Method="TCP/$port"}};$t.Close()}catch{}}
    }

    # Alle Runspaces starten (Pool drosselt automatisch auf $Threads)
    $rs = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($sn in $Subnets) {
        for ($i = 1; $i -le 254; $i++) {
            $ip = "{0}.{1}" -f $sn, $i
            $ps = [System.Management.Automation.PowerShell]::Create()
            $ps.RunspacePool = $pool
            [void]$ps.AddScript($sb).AddArgument($ip).AddArgument($Timeout)
            $rs.Add(@{ PS=$ps; H=$ps.BeginInvoke(); IP=$ip })
        }
    }

    # Ergebnisse einsammeln sobald fertig (non-blocking polling)
    $done = 0
    while ($rs.Count -gt 0) {
        for ($i = $rs.Count - 1; $i -ge 0; $i--) {
            if ($rs[$i].H.IsCompleted) {
                $r = $rs[$i].PS.EndInvoke($rs[$i].H)
                if ($r) { $alive.Add($r) }
                $rs[$i].PS.Dispose()
                $rs.RemoveAt($i)
                $done++
            }
        }
        if ($rs.Count -gt 0) {
            Write-Progress -Activity "Ping-Sweep" `
                -Status ("{0}/{1} erledigt  |  aktiv: {2}  |  gefunden: {3}" -f $done,$total,$rs.Count,$alive.Count) `
                -PercentComplete ([int]($done * 100 / $total))
            Start-Sleep -Milliseconds 80
        }
    }

    Write-Progress -Activity "Ping-Sweep" -Completed
    $pool.Close() ; $pool.Dispose()

    $sorted = $alive | Sort-Object {
        $p = $_.IP.Split('.') ; [int]$p[0]*16777216+[int]$p[1]*65536+[int]$p[2]*256+[int]$p[3]
    }
    Write-C ("    => {0} Hosts erreichbar" -f @($sorted).Count) Green
    return $sorted
}

# -- Detail-Scan ------------------------------------------------------------
function Start-DetailScan([object[]]$Candidates, [PSCustomObject[]]$Ifaces) {
    Write-C '[2/3] Detail-Scan (Status, MAC, DNS, Namen, WMI/CIM, SNMP, Ports) ...' Cyan
    $nr=0;$total=$Candidates.Count
    foreach($c in $Candidates){
        $nr++;$ip=[string]$c.IP;$online=[bool]$c.Online
        Write-Progress -Activity 'Detail-Scan' -Status ("{0} ({1}/{2}) - {3}" -f $ip,$nr,$total,(if($online){'Online'}else{'Offline/bekannt'})) -PercentComplete ($nr/$total*100)
        $pts=$ip.Split('.');$sn="{0}.{1}.{2}"-f$pts[0],$pts[1],$pts[2];$ifc=$Ifaces|Where-Object{$_.Subnet-eq$sn}|Select-Object -First 1
        $vlan=if($script:VlanMap.ContainsKey($sn)){$script:VlanMap[$sn]}else{0};$gw=if($ifc){$ifc.Gateway}else{'-'};$plen=if($ifc){$ifc.PrefixLength}else{24}
        $mac=if($c.MAC -and $c.MAC-ne'-'){$c.MAC}else{Get-MacFromARP $ip};if($ifc-and$ifc.IPAddress-eq$ip){$mac=$ifc.MacAddress}
        $dns=if($c.Name -and $c.Name-ne'-'){$c.Name}else{'-'};if($online){try{$dns=([System.Net.Dns]::GetHostEntry($ip)).HostName}catch{}}
        $nb=if($online){Get-NetBIOSName $ip}else{'-'};$wmi=if($online){Get-WMIDetails $ip}else{@{OS='';Build='';CompName='';Domain='';Desc=''}}
        $sDesc=$null;$sName=$null;$sLoc=$null;$ports='';if($online){$sDesc=Invoke-SNMPGet $ip '1.3.6.1.2.1.1.1.0' $SNMPCommunity;$sName=Invoke-SNMPGet $ip '1.3.6.1.2.1.1.5.0' $SNMPCommunity;$sLoc=Invoke-SNMPGet $ip '1.3.6.1.2.1.1.6.0' $SNMPCommunity;$ports=Get-OpenPorts $ip}
        $swPort=if($ifc){"Interface: $($ifc.AdapterName)"}else{'-'};$swName='-';if($online-and$gw-and$gw-ne'-'){$gn=Invoke-SNMPGet $gw '1.3.6.1.2.1.1.5.0' $SNMPCommunity;if($gn){$swName=$gn}}
        $dev=[PSCustomObject]@{Nr=$nr;Status=if($online){'Online'}else{'Offline / zuletzt bekannt'};Online=$online;DiscoveryMethod=$c.Method;DiscoverySource=$c.Source;LastSeen=$c.LastSeen;IP=$ip;Hostname=$dns;NetBIOS=$nb;MAC=$mac;Vendor=(Get-Vendor $mac);Subnet=$sn;Prefix=$plen;VlanID=$vlan;Gateway=$gw;WMI_OS=$wmi.OS;WMI_Build=$wmi.Build;WMI_Name=$wmi.CompName;WMI_Domain=$wmi.Domain;WMI_Desc=$wmi.Desc;SNMP_Descr=$sDesc;SNMP_Name=$sName;SNMP_Loc=$sLoc;OpenPorts=$ports;SwPort=$swPort;SwName=$swName;DeviceType=''}
        $dev.DeviceType=Get-DeviceType $dev;$script:AllDevices.Add($dev)
    }
    Write-Progress -Activity 'Detail-Scan' -Completed
    Write-C ("    => {0} Geraete erfasst ({1} online, {2} offline/bekannt)" -f $script:AllDevices.Count,@($script:AllDevices|Where-Object Online).Count,@($script:AllDevices|Where-Object{-not$_.Online}).Count) Green
}

# -- HTML-Report ------------------------------------------------------------
function Export-HTML([string]$Path) {
    $bySubnet = $script:AllDevices | Group-Object Subnet | Sort-Object Name
    $pal = @("#4fc3f7","#81c784","#ffb74d","#ce93d8","#80deea","#ef9a9a","#a5d6a7","#ffe082")
    $pi  = 0 ; $rows = ""
    foreach ($sg in $bySubnet) {
        $first  = $sg.Group | Select-Object -First 1
        $vlan   = $first.VlanID ; $gw = $first.Gateway ; $plen = $first.Prefix
        $col    = $pal[$pi % $pal.Count] ; $pi++
        $vStr   = if ($vlan -gt 0) { "VLAN $vlan" } else { "kein VLAN-Tag" }
        $rows  += "<tr class='sh'><td colspan='9' style='border-left:4px solid $col;color:$col'>"
        $rows  += "&#9658; &nbsp; Subnetz: $($sg.Name).0/$plen &nbsp;|&nbsp; $vStr &nbsp;|&nbsp; GW: $gw &nbsp;|&nbsp; $($sg.Group.Count) Geraet(e)</td></tr>"
        foreach ($d in ($sg.Group | Sort-Object { [Version]$_.IP })) {
            $ico  = if ($ICONS.ContainsKey($d.DeviceType)) { $ICONS[$d.DeviceType] } else { "[?]" }
            $name = if ($d.WMI_Name) { $d.WMI_Name } elseif ($d.NetBIOS -ne "-") { $d.NetBIOS } else { $d.Hostname }
            $os   = if ($d.WMI_OS)   { $d.WMI_OS }   elseif ($d.SNMP_Descr) { ($d.SNMP_Descr -replace '\n',' ').Substring(0,[Math]::Min(60,$d.SNMP_Descr.Length)) } else { "-" }
            $sp   = if ($d.SwPort -ne "-") { $d.SwPort + (if ($d.SwName -ne "-") {" via " + $d.SwName} else {""}) } else { "-" }
            $rows += "<tr class='dr' onclick='tgl(this)'>"
            $statusClass=if($d.Online){'on'}else{'off'}
            $rows += "<td class='$statusClass'>$($d.Status)</td><td><code style='color:$col'>$ico</code> $($d.DeviceType)</td>"
            $rows += "<td>$($d.IP)</td><td>$(if($name -and $name -ne '-'){$name}else{'-'})</td>"
            $rows += "<td><code>$($d.MAC)</code></td><td>$($d.Vendor)</td>"
            $rows += "<td>$os</td><td>$sp</td>"
            $rows += "<td style='font-size:.8em;color:#888'>$(if($d.OpenPorts){$d.OpenPorts}else{'-'})</td></tr>"
            # Detail-Zeile
            $dBlocks = @(
                "Status",$d.Status ; "Erkennung",$d.DiscoveryMethod ; "Quelle",$d.DiscoverySource ; "Zuletzt bekannt",(if($d.LastSeen){$d.LastSeen}else{"-"}) ; "IP",$d.IP ; "MAC",$d.MAC ; "Hersteller",$d.Vendor
                "Hostname (DNS)",$d.Hostname ; "NetBIOS",$d.NetBIOS
                "SNMP-Name",(if($d.SNMP_Name){$d.SNMP_Name}else{"-"})
                "OS / System",(if($d.WMI_OS){$d.WMI_OS}else{"-"})
                "OS-Build",(if($d.WMI_Build){$d.WMI_Build}else{"-"})
                "Computer-Name",(if($d.WMI_Name){$d.WMI_Name}else{"-"})
                "Domain / Workgroup",(if($d.WMI_Domain){$d.WMI_Domain}else{"-"})
                "Beschreibung (WMI)",(if($d.WMI_Desc){$d.WMI_Desc}else{"-"})
                "SNMP sysDescr",(if($d.SNMP_Descr){$d.SNMP_Descr.Substring(0,[Math]::Min(80,$d.SNMP_Descr.Length))}else{"-"})
                "SNMP Standort",(if($d.SNMP_Loc){$d.SNMP_Loc}else{"-"})
                "Subnetz",("{0}.0/{1}" -f $d.Subnet,$d.Prefix)
                "VLAN",(if($d.VlanID -gt 0){"VLAN $($d.VlanID)"}else{"kein 802.1Q-Tag"})
                "Default Gateway",$d.Gateway
                "Switch / Port",$sp
                "Offene Ports",(if($d.OpenPorts){$d.OpenPorts}else{"-"})
            )
            $dHtml = ""
            for ($di=0; $di -lt $dBlocks.Count; $di+=2) {
                $dHtml += "<div><b>$($dBlocks[$di]):</b> $($dBlocks[$di+1])</div>"
            }
            $rows += "<tr class='det'><td colspan='9'><div class='dbox'><div class='dg'>$dHtml</div></div></td></tr>"
        }
    }
    $date = Get-Date -f "dd.MM.yyyy HH:mm:ss"
    $cnt  = $script:AllDevices.Count
    $html = @"
<!DOCTYPE html><html lang="de">
<head><meta charset="UTF-8">
<title>Netzwerk-Scan - Reith IT GmbH</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0a0a14;color:#d0d0e0;font-family:'Segoe UI',Consolas,monospace;font-size:13px}
header{background:linear-gradient(135deg,#0d1b3e,#050510);padding:16px 24px;border-bottom:2px solid #1e2a50;display:flex;justify-content:space-between;align-items:center}
header h1{font-size:1.2em;color:#4fc3f7;letter-spacing:3px;text-transform:uppercase}
header .m{color:#666;font-size:.85em}
.bar{padding:8px 24px;background:#0c0c1e;display:flex;gap:10px;border-bottom:1px solid #1a1a2e;flex-wrap:wrap;align-items:center}
.bar input{background:#12122e;border:1px solid #2a2a5a;color:#d0d0e0;padding:5px 12px;border-radius:3px;width:240px}
.bar input:focus{outline:none;border-color:#4fc3f7}
.bar button{background:#0d1b3e;color:#4fc3f7;border:1px solid #2a4a7f;padding:5px 14px;border-radius:3px;cursor:pointer;font-size:.85em}
.bar button:hover{background:#1a2a5e}
.stats{padding:6px 24px;background:#080818;display:flex;gap:20px;border-bottom:1px solid #12122e;flex-wrap:wrap}
.stats span{color:#666;font-size:.82em} .stats b{color:#4fc3f7}
table{width:100%;border-collapse:collapse}
th{background:#0c0c22;color:#4fc3f7;padding:8px 12px;text-align:left;font-size:.82em;text-transform:uppercase;letter-spacing:1px;position:sticky;top:0;z-index:5;border-bottom:2px solid #1a1a3a}
.sh td{padding:7px 14px;font-weight:bold;font-size:.95em;background:#0f0f1e;cursor:default}
.dr{cursor:pointer;transition:background .1s}
.dr:hover{background:#111128}
.dr td{padding:6px 12px;border-bottom:1px solid #111128}
.det td{background:#0a0a1a;padding:0}
.dbox{padding:12px 18px;margin:3px 6px;background:#0d0d26;border-left:3px solid #4fc3f7;border-radius:3px}
.dg{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:5px 16px}
.dg div{font-size:.85em;padding:2px 0} .dg b{color:#4fc3f7}.on{color:#81c784;font-weight:bold}.off{color:#ef9a9a;font-weight:bold;opacity:.9}
footer{padding:10px 24px;color:#333;font-size:.78em;text-align:center;border-top:1px solid #111128;margin-top:6px}
code{font-family:Consolas,monospace}
</style></head><body>
<header>
  <h1>&#9881; Netzwerk-Scan Report</h1>
  <div class="m">Reith IT GmbH &nbsp;|&nbsp; Giuseppe Groth &nbsp;|&nbsp; $date</div>
</header>
<div class="bar">
  <input id="q" type="text" placeholder="Suchen (IP, Name, MAC, Typ, VLAN...)" oninput="flt()">
  <button onclick="document.querySelectorAll('.det').forEach(r=>r.style.display='none')">Alle zuklappen</button>
  <button onclick="document.querySelectorAll('.det').forEach(r=>r.style.display='table-row')">Alle aufklappen</button>
  <button onclick="dlCSV()">CSV herunterladen</button>
</div>
<div class="stats">
  <span><b>$cnt</b> Geraete</span><span><b>$(($script:AllDevices|Where-Object Online).Count)</b> online</span><span><b>$(($script:AllDevices|Where-Object{-not$_.Online}).Count)</b> offline/bekannt</span>
  <span><b>$($bySubnet.Count)</b> Subnetze</span>
  <span><b>$(($script:AllDevices | Where-Object {$_.VlanID -gt 0} | Select-Object VlanID -Unique).Count)</b> VLANs getaggt</span>
  <span><b>$(($script:AllDevices | Where-Object {$_.WMI_OS -ne ""}).Count)</b> Windows via WMI</span>
  <span><b>$(($script:AllDevices | Where-Object {$_.SNMP_Name}).Count)</b> SNMP-faehig</span>
</div>
<div style="overflow-x:auto">
<table>
<thead><tr>
  <th>Status</th><th>Typ</th><th>IP-Adresse</th><th>Name / Hostname</th>
  <th>MAC-Adresse</th><th>Hersteller</th><th>OS / Beschreibung</th>
  <th>Switch / Port</th><th>Dienste (Ports)</th>
</tr></thead>
<tbody id="tb">$rows</tbody></table></div>
<footer>Copyright &copy; 2026 Giuseppe Groth &ndash; Reith IT GmbH &nbsp;|&nbsp; Get-NetworkDevices-Pro.ps1 v4.0</footer>
<script>
function tgl(r){var n=r.nextElementSibling;if(n&&n.classList.contains('det'))n.style.display=n.style.display==='table-row'?'none':'table-row'}
function flt(){var q=document.getElementById('q').value.toLowerCase();document.querySelectorAll('#tb .dr').forEach(function(r){var d=r.nextElementSibling;var v=!q||r.textContent.toLowerCase().indexOf(q)>-1;r.style.display=v?'':'none';if(d)d.style.display='none'})}
function dlCSV(){var h=['Status','Typ','IP','Name','MAC','Hersteller','OS','Port','Dienste'];var rows=[h];document.querySelectorAll('#tb .dr').forEach(function(r){if(r.style.display==='none')return;var c=r.querySelectorAll('td');var row=[];c.forEach(function(x){row.push('"'+x.textContent.replace(/"/g,'""')+'"')});rows.push(row)});var c=rows.map(function(r){return r.join(';')}).join('\n');var a=document.createElement('a');a.href='data:text/csv;charset=utf-8,\uFEFF'+encodeURIComponent(c);a.download='NetworkScan.csv';a.click()}
</script></body></html>
"@
    $html | Out-File -FilePath $Path -Encoding UTF8
    Write-C ("    => HTML: {0}" -f $Path) Green
}

# -- EXCEL-REPORT -----------------------------------------------------------
function Export-ExcelReport([string]$Path) {
    Write-C "  [*] Pruefe ImportExcel-Modul ..." Cyan

    if (-not (Get-Module -ListAvailable -Name ImportExcel -EA SilentlyContinue)) {
        Write-C "  [*] ImportExcel wird installiert (einmalig, ~10 Sek.) ..." Yellow
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Install-Module ImportExcel -Scope CurrentUser -Force -AllowClobber -EA Stop
            Write-C "  [OK] ImportExcel installiert." Green
        } catch {
            Write-C ("  [!] Installation fehlgeschlagen: {0}" -f $_.Exception.Message) Red
            Write-C "  Tipp: PowerShell als Admin starten oder manuell ausfuehren:" DarkYellow
            Write-C "        Install-Module ImportExcel -Scope CurrentUser -Force" DarkYellow
            return
        }
    }
    Import-Module ImportExcel -EA Stop

    # Farben je Geraete-Typ (RGB)
    $TC = @{
        "Windows 11 PC"       = [System.Drawing.Color]::FromArgb(227,242,253)
        "Windows 10 PC"       = [System.Drawing.Color]::FromArgb(227,242,253)
        "Windows PC"          = [System.Drawing.Color]::FromArgb(227,242,253)
        "Windows PC (Legacy)" = [System.Drawing.Color]::FromArgb(236,245,255)
        "Windows Server"      = [System.Drawing.Color]::FromArgb(232,245,233)
        "Linux/Unix"          = [System.Drawing.Color]::FromArgb(255,253,231)
        "Linux"               = [System.Drawing.Color]::FromArgb(255,253,231)
        "Cisco"               = [System.Drawing.Color]::FromArgb(243,229,245)
        "Juniper"             = [System.Drawing.Color]::FromArgb(243,229,245)
        "MikroTik"            = [System.Drawing.Color]::FromArgb(243,229,245)
        "Router"              = [System.Drawing.Color]::FromArgb(243,229,245)
        "Switch"              = [System.Drawing.Color]::FromArgb(243,229,245)
        "Ubiquiti/UniFi"      = [System.Drawing.Color]::FromArgb(232,234,246)
        "AVM FRITZ!Box"       = [System.Drawing.Color]::FromArgb(232,234,246)
        "Drucker"             = [System.Drawing.Color]::FromArgb(255,248,225)
        "IP-Kamera"           = [System.Drawing.Color]::FromArgb(224,247,250)
        "Access Point"        = [System.Drawing.Color]::FromArgb(224,247,250)
        "Synology NAS"        = [System.Drawing.Color]::FromArgb(230,245,230)
        "NAS"                 = [System.Drawing.Color]::FromArgb(230,245,230)
        "Unbekannt"           = [System.Drawing.Color]::FromArgb(245,245,245)
    }
    $HDR_BG = [System.Drawing.Color]::FromArgb(31,73,125)
    $HDR_FG = [System.Drawing.Color]::White

    function Set-HeaderStyle($ws, [int]$cols) {
        $h = $ws.Cells[1,1,1,$cols]
        $h.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
        $h.Style.Fill.BackgroundColor.SetColor($HDR_BG)
        $h.Style.Font.Color.SetColor($HDR_FG)
        $h.Style.Font.Bold  = $true
        $h.Style.Font.Size  = 10
        $h.Style.Font.Name  = "Arial"
        $ws.Row(1).Height   = 22
        $h.Style.HorizontalAlignment = [OfficeOpenXml.Style.ExcelHorizontalAlignment]::Center
    }

    function Set-DataStyle($ws, [int]$rows, [int]$cols, [int]$typeCol) {
        # Borders
        $all = $ws.Cells[1,1,$rows,$cols]
        $all.Style.Border.Top.Style    = [OfficeOpenXml.Style.ExcelBorderStyle]::Thin
        $all.Style.Border.Bottom.Style = [OfficeOpenXml.Style.ExcelBorderStyle]::Thin
        $all.Style.Border.Left.Style   = [OfficeOpenXml.Style.ExcelBorderStyle]::Thin
        $all.Style.Border.Right.Style  = [OfficeOpenXml.Style.ExcelBorderStyle]::Thin
        $all.Style.Font.Name  = "Arial"
        $all.Style.Font.Size  = 9
        # Zeilenhoehe + Farbkodierung
        for ($r=2; $r-le$rows; $r++) {
            $ws.Row($r).Height = 15
            if ($typeCol -gt 0) {
                $dt = $ws.Cells[$r,$typeCol].Value
                if ($dt -and $TC.ContainsKey($dt)) {
                    $ws.Cells[$r,1,$r,$cols].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
                    $ws.Cells[$r,1,$r,$cols].Style.Fill.BackgroundColor.SetColor($TC[$dt])
                }
            }
        }
    }

    # -- SHEET 1: Alle Geraete ---------------------------------------------
    Write-C "  [1/5] Sheet: Alle Geraete ..." DarkCyan
    $s1 = $script:AllDevices | Sort-Object { [Version]$_.IP } | Select-Object @(
        @{N="Nr";              E={$_.Nr}}
        @{N="Status";          E={$_.Status}}
        @{N="Erkennung";       E={$_.DiscoveryMethod}}
        @{N="Quelle";          E={$_.DiscoverySource}}
        @{N="Zuletzt bekannt"; E={if($_.LastSeen){$_.LastSeen}else{"-"}}}
        @{N="Geraete-Typ";     E={$_.DeviceType}}
        @{N="IP-Adresse";      E={$_.IP}}
        @{N="Hostname (DNS)";  E={$_.Hostname}}
        @{N="NetBIOS-Name";    E={$_.NetBIOS}}
        @{N="MAC-Adresse";     E={$_.MAC}}
        @{N="Hersteller";      E={$_.Vendor}}
        @{N="Subnetz";         E={("{0}.0/{1}" -f $_.Subnet,$_.Prefix)}}
        @{N="VLAN";            E={if($_.VlanID -gt 0){"VLAN $($_.VlanID)"}else{"-"}}}
        @{N="Gateway";         E={$_.Gateway}}
        @{N="Betriebssystem";  E={if($_.WMI_OS){$_.WMI_OS}else{"-"}}}
        @{N="OS-Build";        E={if($_.WMI_Build){$_.WMI_Build}else{"-"}}}
        @{N="Computername";    E={if($_.WMI_Name){$_.WMI_Name}else{"-"}}}
        @{N="Domain";          E={if($_.WMI_Domain){$_.WMI_Domain}else{"-"}}}
        @{N="Beschreibung";    E={if($_.WMI_Desc){$_.WMI_Desc}elseif($_.SNMP_Descr){$_.SNMP_Descr.Substring(0,[Math]::Min(60,$_.SNMP_Descr.Length))}else{"-"}}}
        @{N="SNMP-Name";       E={if($_.SNMP_Name){$_.SNMP_Name}else{"-"}}}
        @{N="SNMP-Standort";   E={if($_.SNMP_Loc){$_.SNMP_Loc}else{"-"}}}
        @{N="Switch / Port";   E={if($_.SwPort -ne "-"){$_.SwPort}else{"-"}}}
        @{N="Switch-Hostname"; E={if($_.SwName -ne "-"){$_.SwName}else{"-"}}}
        @{N="Offene Ports";    E={if($_.OpenPorts){$_.OpenPorts}else{"-"}}}
    )
    $xl = $s1 | Export-Excel -Path $Path -WorksheetName "Alle Geraete" `
        -AutoFilter -FreezeTopRow -AutoSize -PassThru -TableStyle Medium2
    $ws1 = $xl.Workbook.Worksheets["Alle Geraete"]
    Set-HeaderStyle $ws1 24
    Set-DataStyle   $ws1 ($s1.Count+1) 24 6   # Spalte 2 = Geraete-Typ
    $ws1.View.TabSelected = $true

    # -- SHEET 2: Subnetz-Uebersicht --------------------------------------
    Write-C "  [2/5] Sheet: Subnetz-Uebersicht ..." DarkCyan
    $s2 = $script:AllDevices | Group-Object Subnet | Sort-Object Name | ForEach-Object {
        $g = $_ ; $f = $g.Group | Select-Object -First 1
        [PSCustomObject]@{
            "Subnetz"           = ("{0}.0/{1}" -f $g.Name,$f.Prefix)
            "VLAN"              = if ($f.VlanID -gt 0) {"VLAN $($f.VlanID)"} else {"-"}
            "Gateway"           = $f.Gateway
            "Gesamt"            = $g.Group.Count
            "Windows"           = @($g.Group | Where-Object {$_.WMI_OS -ne ""}).Count
            "Linux / Unix"      = @($g.Group | Where-Object {$_.DeviceType -match "Linux"}).Count
            "Netzwerkgeraete"   = @($g.Group | Where-Object {$_.DeviceType -match "Cisco|Juniper|Router|Switch|MikroTik|Ubiquiti|AVM"}).Count
            "Drucker"           = @($g.Group | Where-Object {$_.DeviceType -match "Drucker"}).Count
            "NAS / Storage"     = @($g.Group | Where-Object {$_.DeviceType -match "NAS|Synology"}).Count
            "Sonstige / Unbek." = @($g.Group | Where-Object {$_.DeviceType -eq "Unbekannt"}).Count
        }
    }
    $xl = $s2 | Export-Excel -ExcelPackage $xl -WorksheetName "Subnetz-Uebersicht" `
        -AutoFilter -FreezeTopRow -AutoSize -PassThru -TableStyle Medium9
    $ws2 = $xl.Workbook.Worksheets["Subnetz-Uebersicht"]
    Set-HeaderStyle $ws2 10
    Set-DataStyle   $ws2 ($s2.Count+1) 10 0
    # Gesamt-Spalte (4) fett
    for ($r=2; $r-le($s2.Count+1); $r++) { $ws2.Cells[$r,4].Style.Font.Bold=$true }

    # -- SHEET 3: Windows-Geraete -----------------------------------------
    Write-C "  [3/5] Sheet: Windows-Geraete ..." DarkCyan
    $winDevs = @($script:AllDevices | Where-Object {$_.WMI_OS -ne ""} | Sort-Object {[Version]$_.IP})
    if ($winDevs.Count -gt 0) {
        $s3 = $winDevs | Select-Object @(
            @{N="IP-Adresse";      E={$_.IP}}
            @{N="Geraete-Typ";     E={$_.DeviceType}}
            @{N="Computername";    E={if($_.WMI_Name){$_.WMI_Name}else{"-"}}}
            @{N="Domain";          E={if($_.WMI_Domain){$_.WMI_Domain}else{"-"}}}
            @{N="Betriebssystem";  E={$_.WMI_OS}}
            @{N="OS-Build";        E={if($_.WMI_Build){$_.WMI_Build}else{"-"}}}
            @{N="Beschreibung";    E={if($_.WMI_Desc){$_.WMI_Desc}else{"-"}}}
            @{N="MAC-Adresse";     E={$_.MAC}}
            @{N="Subnetz";         E={("{0}.0/{1}" -f $_.Subnet,$_.Prefix)}}
            @{N="VLAN";            E={if($_.VlanID -gt 0){"VLAN $($_.VlanID)"}else{"-"}}}
            @{N="RDP (3389)";      E={if($_.OpenPorts -match "3389"){"Ja"}else{"Nein"}}}
            @{N="SMB (445)";       E={if($_.OpenPorts -match "445") {"Ja"}else{"Nein"}}}
            @{N="WinRM (5985)";    E={if($_.OpenPorts -match "5985"){"Ja"}else{"Nein"}}}
            @{N="Switch / Port";   E={if($_.SwPort -ne "-"){$_.SwPort}else{"-"}}}
        )
        $xl = $s3 | Export-Excel -ExcelPackage $xl -WorksheetName "Windows-Geraete" `
            -AutoFilter -FreezeTopRow -AutoSize -PassThru -TableStyle Medium6
        $ws3 = $xl.Workbook.Worksheets["Windows-Geraete"]
        Set-HeaderStyle $ws3 14
        Set-DataStyle   $ws3 ($s3.Count+1) 14 2   # Spalte 2 = Geraete-Typ
        # RDP/SMB/WinRM Ja=gruen, Nein=hellrot
        $srvColor = [System.Drawing.Color]::FromArgb(198,239,206)
        $noColor  = [System.Drawing.Color]::FromArgb(255,235,235)
        foreach ($col in @(11,12,13)) {
            for ($r=2; $r-le($s3.Count+1); $r++) {
                $v = $ws3.Cells[$r,$col].Value
                $c = if ($v -eq "Ja") { $srvColor } else { $noColor }
                $ws3.Cells[$r,$col].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
                $ws3.Cells[$r,$col].Style.Fill.BackgroundColor.SetColor($c)
                $ws3.Cells[$r,$col].Style.Font.Bold = ($v -eq "Ja")
            }
        }
    }

    # -- SHEET 4: Netzwerk-Interfaces -------------------------------------
    Write-C "  [4/5] Sheet: Netzwerk-Interfaces ..." DarkCyan
    $s4 = $script:Interfaces | Select-Object @(
        @{N="Adapter-Name";  E={$_.AdapterName}}
        @{N="Beschreibung";  E={$_.Description}}
        @{N="IP-Adresse";    E={$_.IPAddress}}
        @{N="Subnetzmaske";  E={"/{0}" -f $_.PrefixLength}}
        @{N="Gateway";       E={$_.Gateway}}
        @{N="VLAN-ID";       E={if($_.VlanID -gt 0){"VLAN $($_.VlanID)"}else{"-"}}}
        @{N="MAC-Adresse";   E={$_.MacAddress}}
        @{N="Link-Speed";    E={$_.LinkSpeed}}
        @{N="LLDP Tx";       E={$_.LldpTx}}
        @{N="LLDP Rx";       E={$_.LldpRx}}
    )
    $xl = $s4 | Export-Excel -ExcelPackage $xl -WorksheetName "Netzwerk-Interfaces" `
        -AutoFilter -FreezeTopRow -AutoSize -PassThru -TableStyle Medium4
    $ws4 = $xl.Workbook.Worksheets["Netzwerk-Interfaces"]
    Set-HeaderStyle $ws4 10
    Set-DataStyle   $ws4 ($s4.Count+1) 10 0

    # -- SHEET 5: Info & Legende -------------------------------------------
    Write-C "  [5/5] Sheet: Info & Legende ..." DarkCyan
    $xl = Export-Excel -ExcelPackage $xl -WorksheetName "Info" -PassThru
    $wsi = $xl.Workbook.Worksheets["Info"]
    $wsi.Column(1).Width = 28 ; $wsi.Column(2).Width = 45

    function InfoCell($ws,[string]$addr,[string]$val,[bool]$bold=$false,[int]$sz=10,[string]$hex="") {
        $ws.Cells[$addr].Value      = $val
        $ws.Cells[$addr].Style.Font.Bold = $bold
        $ws.Cells[$addr].Style.Font.Size = $sz
        $ws.Cells[$addr].Style.Font.Name = "Arial"
        if ($hex -ne "") {
            $ws.Cells[$addr].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
            $r2=[Convert]::ToInt32($hex.Substring(0,2),16)
            $g2=[Convert]::ToInt32($hex.Substring(2,2),16)
            $b2=[Convert]::ToInt32($hex.Substring(4,2),16)
            $ws.Cells[$addr].Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::FromArgb($r2,$g2,$b2))
        }
    }

    InfoCell $wsi "A1" "Netzwerk-Scan Report" $true 16
    $wsi.Cells["A1"].Style.Font.Color.SetColor([System.Drawing.Color]::FromArgb(31,73,125))
    InfoCell $wsi "A3" "Erstellt am:"    $true
    InfoCell $wsi "B3" (Get-Date -f "dd.MM.yyyy HH:mm:ss")
    InfoCell $wsi "A4" "Script:"         $true
    InfoCell $wsi "B4" "Get-NetworkDevices-Pro.ps1 v4.0"
    InfoCell $wsi "A5" "Copyright:"      $true
    InfoCell $wsi "B5" "Giuseppe Groth - Reith IT GmbH"
    $wsi.Cells["A3:B5"].Style.Font.Name = "Arial"
    $wsi.Cells["A3:B5"].Style.Font.Size = 9

    InfoCell $wsi "A7" "Scan-Statistik" $true 11
    $stats = @(
        @("A8","B8","Geraete gesamt",     $script:AllDevices.Count)
        @("A9","B9","Subnetze",           @($script:AllDevices|Select-Object Subnet -Unique).Count)
        @("A10","B10","VLANs (getaggt)",  @($script:AllDevices|Where-Object{$_.VlanID-gt 0}|Select-Object VlanID -Unique).Count)
        @("A11","B11","Windows-Geraete",  @($script:AllDevices|Where-Object{$_.WMI_OS-ne""}).Count)
        @("A12","B12","Linux-Geraete",    @($script:AllDevices|Where-Object{$_.DeviceType-match"Linux"}).Count)
        @("A13","B13","Netzwerkgeraete",  @($script:AllDevices|Where-Object{$_.DeviceType-match"Cisco|Router|Switch|MikroTik|Ubiquiti|AVM"}).Count)
        @("A14","B14","Drucker",          @($script:AllDevices|Where-Object{$_.DeviceType-match"Drucker"}).Count)
        @("A15","B15","Unbekannt",        @($script:AllDevices|Where-Object{$_.DeviceType-eq"Unbekannt"}).Count)
    )
    foreach ($st in $stats) {
        InfoCell $wsi $st[0] $st[2] $true
        $wsi.Cells[$st[1]].Value = $st[3]
        $wsi.Cells[$st[1]].Style.Font.Name = "Arial"
        $wsi.Cells[$st[1]].Style.Font.Size = 9
    }

    InfoCell $wsi "A17" "Farblegende (Sheet: Alle Geraete)" $true 11
    $legend = @(
        @("Windows 11 / Windows 10 PC", "E3F2FD")
        @("Windows Server",             "E8F5E9")
        @("Linux / Unix",               "FFFDE7")
        @("Cisco / Router / Switch",    "F3E5F5")
        @("Ubiquiti / AVM FRITZ!Box",   "E8EAF6")
        @("Drucker / MFG",              "FFF8E1")
        @("IP-Kamera / Access Point",   "E0F7FA")
        @("NAS / Storage",              "E6F4E6")
        @("Unbekannt",                  "F5F5F5")
    )
    $lr = 18
    foreach ($lg in $legend) {
        InfoCell $wsi "A$lr" $lg[0] $false 9 $lg[1]
        $wsi.Cells["A$lr"].Style.Border.BorderAround([OfficeOpenXml.Style.ExcelBorderStyle]::Thin)
        $lr++
    }

    # Tabs sortieren
    $xl.Workbook.Worksheets["Alle Geraete"].View.TabSelected     = $true
    $xl.Workbook.Worksheets["Alle Geraete"].View.TabColor.SetColor([System.Drawing.Color]::FromArgb(31,73,125))
    $xl.Workbook.Worksheets["Subnetz-Uebersicht"].View.TabColor.SetColor([System.Drawing.Color]::FromArgb(56,142,60))
    $xl.Workbook.Worksheets["Windows-Geraete"].View.TabColor.SetColor([System.Drawing.Color]::FromArgb(21,101,192))
    $xl.Workbook.Worksheets["Netzwerk-Interfaces"].View.TabColor.SetColor([System.Drawing.Color]::FromArgb(123,31,162))
    $xl.Workbook.Worksheets["Info"].View.TabColor.SetColor([System.Drawing.Color]::FromArgb(130,130,130))

    $xl.Save()
    $xl.Dispose()
    Write-C ("    => Excel: {0}" -f $Path) Green
}

# -- TUI Menu ---------------------------------------------------------------
$script:TUI_Items  = $null
$script:TUI_Sel    = 0
$script:TUI_Scroll = 0
$script:TUI_Mode   = "list"
$script:TUI_Det    = $null

function Build-TUIItems {
    $items = [System.Collections.Generic.List[hashtable]]::new()
    $script:AllDevices | Group-Object Subnet | Sort-Object Name | ForEach-Object {
        $first = $_.Group | Select-Object -First 1
        $items.Add(@{T="H";Subnet=$_.Name;VlanID=$first.VlanID;GW=$first.Gateway;Prefix=$first.Prefix;Cnt=$_.Group.Count})
        $_.Group | Sort-Object { [Version]$_.IP } | ForEach-Object { $items.Add(@{T="D";Data=$_}) }
    }
    $script:TUI_Items = $items
    $script:TUI_Sel   = 0
    for ($i=0; $i -lt $items.Count; $i++) { if ($items[$i].T -eq "D") { $script:TUI_Sel=$i; break } }
}

function Draw-TUIList {
    Clear-Host
    $w = [Console]::WindowWidth
    $pageSize = [Math]::Max(8, [Console]::WindowHeight - 9)
    if ($script:TUI_Sel -lt $script:TUI_Scroll) { $script:TUI_Scroll = $script:TUI_Sel }
    if ($script:TUI_Sel -ge $script:TUI_Scroll + $pageSize) { $script:TUI_Scroll = $script:TUI_Sel - $pageSize + 1 }
    Write-Host ("=" * $w) -ForegroundColor Cyan
    $hdr = ("  NETZWERK-SCANNER v4.0  |  Giuseppe Groth - Reith IT GmbH  |  {0} Geraete  |  {1}" -f $script:AllDevices.Count,(Get-Date -f "HH:mm:ss"))
    Write-Host $hdr.PadRight($w) -ForegroundColor Cyan
    Write-Host ("=" * $w) -ForegroundColor Cyan
    $nav = "  Pfeil: Navigieren  |  Enter: Details  |  H: HTML  |  E: Excel  |  C: CSV  |  Q: Beenden"
    Write-Host $nav.PadRight($w) -ForegroundColor DarkGray
    Write-Host ("-" * $w) -ForegroundColor DarkGray
    $shown = 0
    for ($i=$script:TUI_Scroll; $i -lt $script:TUI_Items.Count -and $shown -lt $pageSize; $i++) {
        $item = $script:TUI_Items[$i]
        $sel  = ($i -eq $script:TUI_Sel)
        if ($item.T -eq "H") {
            $vStr = if ($item.VlanID -gt 0) {"VLAN $($item.VlanID)"} else {"kein VLAN"}
            Write-Host ""
            Write-Host ("  >> SUBNETZ: $($item.Subnet).0/$($item.Prefix)  |  $vStr  |  GW: $($item.GW)  |  $($item.Cnt) Geraet(e)").PadRight($w) -ForegroundColor Magenta
            Write-Host ("  " + ("-" * ($w-4))) -ForegroundColor DarkGray
        } else {
            $d    = $item.Data
            $dt   = $d.DeviceType
            $ico  = if ($ICONS.ContainsKey($dt)) { $ICONS[$dt] } else { "[ ? ]" }
            $name = if ($d.WMI_Name) { $d.WMI_Name } elseif ($d.NetBIOS -ne "-") { $d.NetBIOS } else { $d.Hostname }
            if ($name.Length -gt 26) { $name = $name.Substring(0,23)+"..." }
            $col  = if ($DCOLORS.ContainsKey($dt)) { [ConsoleColor]$DCOLORS[$dt] } else { [ConsoleColor]::DarkGray }
            $st=if($d.Online){"[ON ]"}else{"[OFF]"}
            $ln   = "  {0} $st {1}  {2}  {3}  {4}  {5}" -f (if($sel){">"} else{" "}), $d.IP.PadRight(16), $name.PadRight(28), $d.MAC.PadRight(20), $ico, $dt
            if ($sel) { [Console]::BackgroundColor=[ConsoleColor]::DarkBlue ; [Console]::ForegroundColor=[ConsoleColor]::White ; Write-Host $ln.PadRight($w) ; [Console]::ResetColor() }
            else      { Write-Host $ln -ForegroundColor $col }
            $shown++
        }
    }
    Write-Host ""
    Write-Host ("=" * $w) -ForegroundColor DarkGray
    Write-Host ("  Pos: $($script:TUI_Sel+1)/$($script:TUI_Items.Count)  |  Windows: $(($script:AllDevices|Where-Object{$_.WMI_OS}).Count)  |  Linux: $(($script:AllDevices|Where-Object{$_.DeviceType-match'Linux'}).Count)  |  Drucker: $(($script:AllDevices|Where-Object{$_.DeviceType-match'Drucker'}).Count)  |  Unbekannt: $(($script:AllDevices|Where-Object{$_.DeviceType-eq'Unbekannt'}).Count)").PadRight($w) -ForegroundColor DarkGray
}

function Draw-TUIDetail([PSCustomObject]$d) {
    Clear-Host
    $w = [Console]::WindowWidth
    Write-Host ("=" * $w) -ForegroundColor Cyan
    $hdr = ("  DETAILS: {0}  |  {1}  |  ESC / Q = Zurueck" -f $d.IP,$d.DeviceType)
    Write-Host $hdr.PadRight($w) -ForegroundColor Cyan
    Write-Host ("=" * $w) -ForegroundColor Cyan
    Write-Host ""
    function Row([string]$L,[string]$V,[string]$C="White"){Write-Host ("  {0,-30}" -f ($L+":")) -ForegroundColor DarkGray -NoNewline ; Write-Host $V -ForegroundColor ([ConsoleColor]$C)}
    Write-Host "  -- NETZWERK ----------------------------------------------------------" -ForegroundColor DarkCyan
    Row "Status"              $d.Status (if($d.Online){"Green"}else{"Red"})
    Row "Erkennungsweg"       $d.DiscoveryMethod
    Row "Quelle"              $d.DiscoverySource
    Row "Zuletzt bekannt"     (if($d.LastSeen){$d.LastSeen}else{"-"})
    Row "IP-Adresse"          $d.IP "Cyan"
    Row "Subnetz"             ("{0}.0/{1}" -f $d.Subnet,$d.Prefix)
    Row "VLAN"                (if($d.VlanID -gt 0){"VLAN $($d.VlanID)"}else{"kein 802.1Q-Tag"}) "Yellow"
    Row "Default Gateway"     $d.Gateway
    Row "MAC-Adresse"         $d.MAC "Cyan"
    Row "Hersteller (OUI)"    $d.Vendor
    Write-Host ""
    Write-Host "  -- IDENTIFIKATION ----------------------------------------------------" -ForegroundColor DarkCyan
    Row "Hostname (DNS)"      $d.Hostname "Green"
    Row "NetBIOS-Name"        $d.NetBIOS "Green"
    Row "WMI Computer-Name"   (if($d.WMI_Name){$d.WMI_Name}else{"-"}) "Green"
    Row "SNMP sysName"        (if($d.SNMP_Name){$d.SNMP_Name}else{"-"}) "Green"
    Row "Domain / Workgroup"  (if($d.WMI_Domain){$d.WMI_Domain}else{"-"})
    Row "Beschreibung (WMI)"  (if($d.WMI_Desc){$d.WMI_Desc}else{"-"})
    Write-Host ""
    Write-Host "  -- SYSTEM ------------------------------------------------------------" -ForegroundColor DarkCyan
    Row "Geraete-Typ"         $d.DeviceType "Yellow"
    Row "Betriebssystem"      (if($d.WMI_OS){$d.WMI_OS}else{"-"})
    Row "OS-Build"            (if($d.WMI_Build){$d.WMI_Build}else{"-"})
    Row "SNMP sysDescr"       (if($d.SNMP_Descr){$d.SNMP_Descr.Substring(0,[Math]::Min(65,$d.SNMP_Descr.Length))}else{"-"}) "DarkGray"
    Row "SNMP Standort"       (if($d.SNMP_Loc){$d.SNMP_Loc}else{"-"}) "DarkGray"
    Write-Host ""
    Write-Host "  -- INFRASTRUKTUR / SWITCH-PORT ---------------------------------------" -ForegroundColor DarkCyan
    $sp = if ($d.SwPort -ne "-") { $d.SwPort } else { "nicht ermittelbar (LLDP/SNMP)"}
    Row "Switch-Interface"    $sp "Magenta"
    Row "Switch-Hostname"     (if($d.SwName -ne "-"){$d.SwName}else{"nicht ermittelbar (SNMP)"}) "Magenta"
    Write-Host ""
    Write-Host "  -- OFFENE PORTS / DIENSTE --------------------------------------------" -ForegroundColor DarkCyan
    if ($d.OpenPorts) {
        $parts = $d.OpenPorts -split "  "
        foreach ($pt in $parts) { if ($pt.Trim()) { Row "   $pt" "" "Green" } }
    } else {
        Row "Ports"  "keine offenen Ports gefunden" "DarkGray"
    }
    Write-Host ""
    Write-Host ("=" * $w) -ForegroundColor DarkGray
    Write-Host "  [ESC]  [Q]  [Beliebige Taste]  Zurueck zur Uebersicht" -ForegroundColor DarkGray
}

function Start-TUI {
    if ($script:AllDevices.Count -eq 0) { Write-C "Keine Geraete zum Anzeigen." Red ; return }
    Build-TUIItems
    while ($true) {
        if ($script:TUI_Mode -eq "list") {
            Draw-TUIList
            $k = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            switch ($k.VirtualKeyCode) {
                38 { # Hoch
                    do { $script:TUI_Sel=[Math]::Max(0,$script:TUI_Sel-1) }
                    while ($script:TUI_Sel -gt 0 -and $script:TUI_Items[$script:TUI_Sel].T -eq "H")
                }
                40 { # Runter
                    do { $script:TUI_Sel=[Math]::Min($script:TUI_Items.Count-1,$script:TUI_Sel+1) }
                    while ($script:TUI_Sel -lt $script:TUI_Items.Count-1 -and $script:TUI_Items[$script:TUI_Sel].T -eq "H")
                }
                33 { $script:TUI_Sel=[Math]::Max(0,$script:TUI_Sel-10) }  # PageUp
                34 { $script:TUI_Sel=[Math]::Min($script:TUI_Items.Count-1,$script:TUI_Sel+10) }  # PageDown
                13 { # Enter
                    if ($script:TUI_Items[$script:TUI_Sel].T -eq "D") {
                        $script:TUI_Mode="detail"
                        $script:TUI_Det=$script:TUI_Items[$script:TUI_Sel].Data
                    }
                }
                72 { # H - HTML
                    Export-HTML $HTMLPath
                    Write-Host ""
                    Write-C ("  HTML gespeichert: {0}" -f $HTMLPath) Green
                    Start-Sleep 2
                }
                69 { # E - Excel
                    Write-Host ""
                    Export-ExcelReport $XLSXPath
                    Start-Sleep 2
                }
                67 { # C - CSV
                    $script:AllDevices | Export-Csv -Path $CSVPath -NoTypeInformation -Encoding UTF8 -Delimiter ";"
                    Write-C ("  CSV gespeichert: {0}" -f $CSVPath) Green
                    Start-Sleep 2
                }
                81 { # Q
                    Clear-Host
                    Write-C "Beendet. Copyright (c) 2026 Giuseppe Groth - Reith IT GmbH" DarkGray
                    Write-Host ""
                    return
                }
            }
        } else {
            Draw-TUIDetail $script:TUI_Det
            $k = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            if ($k.VirtualKeyCode -in @(27,81,13,8)) { $script:TUI_Mode="list" }
        }
    }
}

# -- MAIN -------------------------------------------------------------------
function Main {
    Clear-Host
    $w = [Console]::WindowWidth
    Write-Host ("=" * $w) -ForegroundColor Cyan
    Write-Host "  NETZWERK-SCANNER PRO v4.0  |  Giuseppe Groth - Reith IT GmbH".PadRight($w) -ForegroundColor Cyan
    Write-Host ("=" * $w) -ForegroundColor Cyan
    Write-Host ""
    Write-C ("[0/3] Plattform: {0} / PowerShell {1} - erkenne Interfaces, VLANs und Routen ..." -f $script:Platform,$PSVersionTable.PSVersion) Cyan
    $script:Interfaces = Get-LocalInterfaces
    if ($script:Interfaces.Count -eq 0) { Write-C "[FEHLER] Keine aktiven Interfaces!" Red ; return }
    Write-Host ""
    foreach ($ifc in $script:Interfaces) {
        $vStr = if ($ifc.VlanID -gt 0) { "VLAN $($ifc.VlanID)" } else { "kein VLAN" }
        $lStr = if ($ifc.LldpTx -or $ifc.LldpRx) { "LLDP:aktiv" } else { "LLDP:inaktiv" }
        Write-C ("  {0,-20}  {1,-18}/{2}  GW:{3,-18} {4,-15} {5}" -f $ifc.AdapterName,$ifc.IPAddress,$ifc.PrefixLength,$ifc.Gateway,$vStr,$lStr) DarkGray
    }
    Write-Host ""
    $subnets = if ($CustomSubnets.Count -gt 0) {
        Write-C ("  Manuelle Subnetze: {0}" -f ($CustomSubnets -join "  |  ")) DarkCyan
        $CustomSubnets
    } else {
        Find-AllSubnets $script:Interfaces
    }
    Write-Host ""
    $known = @(Get-PassiveKnownDevices)
    $alive = @(Start-PingSweep $subnets)
    Write-Host ""
    $map=@{}
    foreach($a in $alive){$map[$a.IP]=[PSCustomObject]@{IP=$a.IP;Online=$true;Method=$a.Method;Source='Aktiver Scan';MAC='-';Name='-';LastSeen=(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')}}
    foreach($k in $known){if($map.ContainsKey($k.IP)){if($map[$k.IP].MAC-eq'-'){$map[$k.IP].MAC=$k.MAC};if($map[$k.IP].Name-eq'-'){$map[$k.IP].Name=$k.Name};$map[$k.IP].Source+="; $($k.Source)"}else{$map[$k.IP]=[PSCustomObject]@{IP=$k.IP;Online=$false;Method='Passiv / historisch';Source=$k.Source;MAC=$k.MAC;Name=$k.Name;LastSeen=$k.LastSeen}}}
    $candidates=@($map.Values|Sort-Object{[Version]$_.IP})
    if($candidates.Count -eq 0){Write-C 'Keine aktiven oder bekannten Hosts gefunden.' Yellow;return}
    Start-DetailScan $candidates $script:Interfaces
    Write-Host ""
    $script:AllDevices | Export-Csv -Path $CSVPath -NoTypeInformation -Encoding UTF8 -Delimiter ';'
    Write-C ("[+]   CSV: {0}" -f $CSVPath) Green
    if (-not $NoHTML) {
        Write-C "[3/3] Generiere HTML-Report ..." Cyan
        Export-HTML $HTMLPath
    }
    if (-not $NoExcel) {
        Write-C "[+]   Generiere Excel-Report ..." Cyan
        Export-ExcelReport $XLSXPath
    }
    Write-Host ""
    Write-Host ("=" * $w) -ForegroundColor Cyan
    Write-Host ("  Scan fertig: {0} Geraete in {1} Subnetzen  |  {2}" -f $script:AllDevices.Count,$subnets.Count,(Get-Date -f "dd.MM.yyyy HH:mm:ss")).PadRight($w) -ForegroundColor Green
    Write-Host ("=" * $w) -ForegroundColor Cyan
    Write-Host ""
    if ($OpenReport -and -not $NoHTML -and (Test-Path $HTMLPath)) {
        try {
            if ($script:IsWindows) { Start-Process $HTMLPath }
            elseif (Get-Command xdg-open -ErrorAction SilentlyContinue) { & xdg-open $HTMLPath 2>$null }
        } catch {}
    }
    if (-not $NoMenu) { Start-TUI }
}

# Einfacher Modus: sinnvolle Standardwerte ohne Zusatzfragen
if ($SimpleMode) {
    $IncludeHostsFile = $true
    $NoExcel = $true
    $NoMenu = $true
    $OpenReport = $true
}

Main
