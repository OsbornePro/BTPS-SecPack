function Get-MACVendor
{
    [CmdletBinding()]
    param(
        [Parameter(
            Position=0,
            Mandatory=$true,
            HelpMessage='MAC-Address or the first 6 digits of it')]

        [ValidateScript({
                if($_ -match "^(([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})|([0-9A-Fa-f]{2}){6})|([0-9A-Fa-f]{2}[:-]){2}([0-9A-Fa-f]{2})|([0-9A-Fa-f]{2}){3}$")
                {
                    return $true
                }
                else 
                {
                    throw "Enter a valid MAC-Address (like 00:00:00:00:00:00 or 00-00-00-00-00-00)!"    
                }

        })]

        [String[]]$MACAddress

    )

    Begin{

        # MAC-Vendor list path
##########################################################################################################################
        $CSV_MACVendorList_Path = "C:\Users\Public\Documents\PSGetHelp\MAC.Vendor.List.csv"        

        if([System.IO.File]::Exists($CSV_MACVendorList_Path))

        {

            $MAC_VendorList = Import-Csv -Path $CSV_MACVendorList_Path | Select-Object -Property "Assignment", "Organization Name"
            
            #### The above values may change depending on your csv file. Just replaec Assignment and Organization Name with whatever the headers are in your 
        }

        else {

            throw [System.IO.FileNotFoundException] "No CSV-File to assign vendor with MAC-Address found!"

        }

    }

    Process{

        foreach($MACAddress2 in $MACAddress)

        {

            $Vendor = [String]::Empty

            # Split it, so we can search the vendor (XX-XX-XX-XX-XX-XX to XX-XX-XX)            

            $MAC_VendorSearch = $MACAddress2.Replace("-","").Replace(":","").Substring(0,6)

            foreach($ListEntry in $MAC_VendorList)

            {

                if($ListEntry.Assignment -eq $MAC_VendorSearch)

                {

                    $Vendor = $ListEntry."Organization Name"
             
                    [pscustomobject] @{

                        ClientId = $MACAddress2

                        Vendor = $Vendor

                    }

                }

            }                            

        }

    }

    End{

    }

}

