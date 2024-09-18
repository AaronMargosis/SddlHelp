$tabDelimitedTable = $false

$lookup = @{}
$opts = 
    "sddl",
    "ntds",
    "file",
    "dir",
    "pipe",
    "key",
    "service",
    "scm",
    "process",
    "thread",
    "share",
    "com",
    "winsta",
    "desktop",
    "standard"
$opts | %{ 
    $objType = $_

    C:\Projects\Utils\SddlHelp\Release\SddlHelp.exe -rights $_ | %{
        $rightsParts = $_.Split(" ", [System.StringSplitOptions]::RemoveEmptyEntries)
        $hex = $code = $sym = $null
        switch($rightsParts.Length)
        {
        2 { $hex = $rightsParts[0]; $sym = $rightsParts[1] }
        3 { $hex = $rightsParts[0]; $code = $rightsParts[1]; $sym = $rightsParts[2] }
        }

        if ($null -ne $hex)
        {
            $lookupKey = $hex + "  " + $code
            if (-not $lookup.ContainsKey($lookupKey))
            {
                $rights = @{}
                $rights.Add($objType, $sym)
                $lookup.Add($lookupKey, $rights)
            }
            else
            {
                $rights = $lookup[$lookupKey]
                if (-not $rights.ContainsKey($objType))
                {
                    $lookup[$lookupKey].Add($objType, $sym)
                }
            }
        }
    }
}

if ($tabDelimitedTable)
{
    "Hex`tCode`t" + ($opts -join "`t")

    $lookup.Keys | Sort-Object | %{

        $lookupKey = $_
        $rights = $lookup[$lookupKey]
        $lineParts = $lookupKey.Split(" ", [System.StringSplitOptions]::RemoveEmptyEntries)
        if ($lineParts.Length -eq 1)
        {
            $line = $lineParts[0] + "`t"
        }
        else
        {
            $line = $lineParts[0] + "`t" + $lineParts[1]
        }

        $opts | %{
            $line += "`t"
            if ($rights.ContainsKey($_))
            {
                $line += $rights[$_]
            }
            elseif ("sddl" -ne $_ -and $rights.ContainsKey("standard"))
            {
                $line += $rights["standard"]
            }
        }
        $line
    }
}
else
{
    $lookup.Keys | Sort-Object | %{

        $lookupKey = $_
        $lookupKey

        $rights = $lookup[$lookupKey]
        $opts | %{
            if ($rights.ContainsKey($_))
            {
                "`t" + $_ + "`t" + $rights[$_]
            }
        }
    }
}