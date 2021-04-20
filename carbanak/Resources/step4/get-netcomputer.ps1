# Pulled relevant functions from powerview.ps1
filter Get-NetDomain {
    <#
        .SYNOPSIS
            Returns a given domain object.
        .PARAMETER Domain
            The domain name to query for, defaults to the current domain.
        .PARAMETER Credential
            A [Management.Automation.PSCredential] object of alternate credentials
            for connection to the target domain.
        .EXAMPLE
            PS C:\> Get-NetDomain -Domain testlab.local
        .EXAMPLE
            PS C:\> "testlab.local" | Get-NetDomain
        .LINK
            http://social.technet.microsoft.com/Forums/scriptcenter/en-US/0c5b3f83-e528-4d49-92a4-dee31f4b481c/finding-the-dn-of-the-the-domain-without-admodule-in-powershell?forum=ITCG
    #>
    
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Domain,

        [Management.Automation.PSCredential]
        $Credential
    )

    if($Credential) {
        
        Write-Verbose "Using alternate credentials for Get-NetDomain"

        if(!$Domain) {
            # if no domain is supplied, extract the logon domain from the PSCredential passed
            $Domain = $Credential.GetNetworkCredential().Domain
            Write-Verbose "Extracted domain '$Domain' from -Credential"
        }
    
        $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        
        try {
            [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
        }
        catch {
            Write-Verbose "The specified domain does '$Domain' not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid."
            $Null
        }
    }
    elseif($Domain) {
        $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
        try {
            [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
        }
        catch {
            Write-Verbose "The specified domain '$Domain' does not exist, could not be contacted, or there isn't an existing trust."
            $Null
        }
    }
    else {
        [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    }
}

filter Get-DomainSearcher {
    <#
        .SYNOPSIS
            Helper used by various functions that takes an ADSpath and
            domain specifier and builds the correct ADSI searcher object.
        .PARAMETER Domain
            The domain to use for the query, defaults to the current domain.
        .PARAMETER DomainController
            Domain controller to reflect LDAP queries through.
        .PARAMETER ADSpath
            The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
            Useful for OU queries.
        .PARAMETER ADSprefix
            Prefix to set for the searcher (like "CN=Sites,CN=Configuration")
        .PARAMETER PageSize
            The PageSize to set for the LDAP searcher object.
        .PARAMETER Credential
            A [Management.Automation.PSCredential] object of alternate credentials
            for connection to the target domain.
        .EXAMPLE
            PS C:\> Get-DomainSearcher -Domain testlab.local
        .EXAMPLE
            PS C:\> Get-DomainSearcher -Domain testlab.local -DomainController SECONDARY.dev.testlab.local
    #>
    
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [String]
        $ADSprefix,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    if(-not $Credential) {
        if(-not $Domain) {
            $Domain = (Get-NetDomain).name
        }
        elseif(-not $DomainController) {
            try {
                # if there's no -DomainController specified, try to pull the primary DC to reflect queries through
                $DomainController = ((Get-NetDomain).PdcRoleOwner).Name
            }
            catch {
                throw "Get-DomainSearcher: Error in retrieving PDC for current domain"
            }
        }
    }
    elseif (-not $DomainController) {
        # if a DC isn't specified
        try {
            $DomainController = ((Get-NetDomain -Credential $Credential).PdcRoleOwner).Name
        }
        catch {
            throw "Get-DomainSearcher: Error in retrieving PDC for current domain"
        }

        if(!$DomainController) {
            throw "Get-DomainSearcher: Error in retrieving PDC for current domain"
        }
    }

    $SearchString = "LDAP://"

    if($DomainController) {
        $SearchString += $DomainController
        if($Domain){
            $SearchString += '/'
        }
    }

    if($ADSprefix) {
        $SearchString += $ADSprefix + ','
    }

    if($ADSpath) {
        if($ADSpath -Match '^GC://') {
            # if we're searching the global catalog
            $DN = $AdsPath.ToUpper().Trim('/')
            $SearchString = ''
        }
        else {
            if($ADSpath -match '^LDAP://') {
                if($ADSpath -match "LDAP://.+/.+") {
                    $SearchString = ''
                }
                else {
                    $ADSpath = $ADSpath.Substring(7)
                }
            }
            $DN = $ADSpath
        }
    }
    else {
        if($Domain -and ($Domain.Trim() -ne "")) {
            $DN = "DC=$($Domain.Replace('.', ',DC='))"
        }
    }

    $SearchString += $DN
    Write-Verbose "Get-DomainSearcher search string: $SearchString"

    if($Credential) {
        Write-Verbose "Using alternate credentials for LDAP connection"
        $DomainObject = New-Object DirectoryServices.DirectoryEntry($SearchString, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        $Searcher = New-Object System.DirectoryServices.DirectorySearcher($DomainObject)
    }
    else {
        $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
    }

    $Searcher.PageSize = $PageSize
    $Searcher.CacheResults = $False
    $Searcher
}

function Get-NetComputer {
    <#
        .SYNOPSIS
            This function utilizes adsisearcher to query the current AD context
            for current computer objects. Based off of Carlos Perez's Audit.psm1
            script in Posh-SecMod (link below).
        .PARAMETER ComputerName
            Return computers with a specific name, wildcards accepted.
        .PARAMETER SPN
            Return computers with a specific service principal name, wildcards accepted.
        .PARAMETER OperatingSystem
            Return computers with a specific operating system, wildcards accepted.
        .PARAMETER ServicePack
            Return computers with a specific service pack, wildcards accepted.
        .PARAMETER Filter
            A customized ldap filter string to use, e.g. "(description=*admin*)"
        .PARAMETER Printers
            Switch. Return only printers.
        .PARAMETER Ping
            Switch. Ping each host to ensure it's up before enumerating.
        .PARAMETER FullData
            Switch. Return full computer objects instead of just system names (the default).
        .PARAMETER Domain
            The domain to query for computers, defaults to the current domain.
        .PARAMETER DomainController
            Domain controller to reflect LDAP queries through.
        .PARAMETER ADSpath
            The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
            Useful for OU queries.
        
        .PARAMETER SiteName
            The AD Site name to search for computers.
        .PARAMETER Unconstrained
            Switch. Return computer objects that have unconstrained delegation.
        .PARAMETER PageSize
            The PageSize to set for the LDAP searcher object.
        .PARAMETER Credential
            A [Management.Automation.PSCredential] object of alternate credentials
            for connection to the target domain.
        .EXAMPLE
            PS C:\> Get-NetComputer
            
            Returns the current computers in current domain.
        .EXAMPLE
            PS C:\> Get-NetComputer -SPN mssql*
            
            Returns all MS SQL servers on the domain.
        .EXAMPLE
            PS C:\> Get-NetComputer -Domain testing
            
            Returns the current computers in 'testing' domain.
        .EXAMPLE
            PS C:\> Get-NetComputer -Domain testing -FullData
            
            Returns full computer objects in the 'testing' domain.
        .LINK
            https://github.com/darkoperator/Posh-SecMod/blob/master/Audit/Audit.psm1
    #>
    
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $ComputerName = '*',

        [String]
        $SPN,

        [String]
        $OperatingSystem,

        [String]
        $ServicePack,

        [String]
        $Filter,

        [Switch]
        $Printers,

        [Switch]
        $Ping,

        [Switch]
        $FullData,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [String]
        $SiteName,

        [Switch]
        $Unconstrained,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    begin {
        # so this isn't repeated if multiple computer names are passed on the pipeline
        $CompSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize -Credential $Credential
    }

    process {

        if ($CompSearcher) {

            # if we're checking for unconstrained delegation
            if($Unconstrained) {
                Write-Verbose "Searching for computers with for unconstrained delegation"
                $Filter += "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
            }
            # set the filters for the seracher if it exists
            if($Printers) {
                Write-Verbose "Searching for printers"
                # $CompSearcher.filter="(&(objectCategory=printQueue)$Filter)"
                $Filter += "(objectCategory=printQueue)"
            }
            if($SPN) {
                Write-Verbose "Searching for computers with SPN: $SPN"
                $Filter += "(servicePrincipalName=$SPN)"
            }
            if($OperatingSystem) {
                $Filter += "(operatingsystem=$OperatingSystem)"
            }
            if($ServicePack) {
                $Filter += "(operatingsystemservicepack=$ServicePack)"
            }
            if($SiteName) {
                $Filter += "(serverreferencebl=$SiteName)"
            }

            $CompFilter = "(&(sAMAccountType=805306369)(dnshostname=$ComputerName)$Filter)"
            Write-Verbose "Get-NetComputer filter : '$CompFilter'"
            $CompSearcher.filter = $CompFilter

            try {
                $Results = $CompSearcher.FindAll()
                $Results | Where-Object {$_} | ForEach-Object {
                    $Up = $True
                    if($Ping) {
                        # TODO: how can these results be piped to ping for a speedup?
                        $Up = Test-Connection -Count 1 -Quiet -ComputerName $_.properties.dnshostname
                    }
                    if($Up) {
                        # return full data objects
                        if ($FullData) {
                            # convert/process the LDAP fields for each result
                            $Computer = Convert-LDAPProperty -Properties $_.Properties
                            $Computer.PSObject.TypeNames.Add('PowerView.Computer')
                            $Computer
                        }
                        else {
                            # otherwise we're just returning the DNS host name
                            $_.properties.dnshostname
                        }
                    }
                }
                $Results.dispose()
                $CompSearcher.dispose()
            }
            catch {
                Write-Warning "Error: $_"
            }
        }
    }
}