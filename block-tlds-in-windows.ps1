$RuleName = "Block outbound to undesirable domains"

<#

 For domain resolution to work and start to populate the
 Addresses values in Get-NetFirewallDynamicKeywordAddress,
 "Windows Defender Advanced Threat Protection Service"
 must be running.

#>

$DomainsToBlock = @(
 "*.info"
,"*.xyz"
,"*.zip"
,"*.ru"
,"*.info"
) | sort

function Refresh-DomainKeywords($DomainsToBlock)
{
  $KeywordIDs = @()
  foreach($D in $DomainsToBlock)
  {
    $KeywordIDs += (New-NetFirewallDynamicKeywordAddress -Id "{$(New-Guid)}" -Keyword $D -AutoResolve $true -Verbose).Id
  }
  return $KeywordIDs
}

$ActiveKeywordAddresses = @{}
$ActiveKeywordAddresses = Get-NetFirewallDynamicKeywordAddress -PolicyStore PersistentStore -ErrorAction Ignore
$ActiveKeywords = $ActiveKeywordAddresses.Keyword | sort

write-host "Defined keywords:"
$DomainsToBlock

if($ActiveKeywords.Count -eq 0)
{
  write-host "Creating keywords..."
  
  Get-NetFirewallRule -DisplayName $RuleName -ErrorAction Ignore | Remove-NetFirewallRule -Verbose
  Get-NetFirewallDynamicKeywordAddress -PolicyStore PersistentStore -ErrorAction Ignore | Remove-NetFirewallDynamicKeywordAddress -Verbose
  
  $NewKeywordIDs = Refresh-DomainKeywords($DomainsToBlock)
  write-host "New keyword IDs:"
  $NewKeywordIDs

  $nf = New-NetFirewallRule -DisplayName $RuleName -PolicyStore PersistentStore -Profile Any -Direction Outbound -Action Block -RemoteDynamicKeywordAddresses $NewKeywordIds -Verbose
  write-host "New firewall rule created. ID: $($nf.Name) - $RuleName"
}
else
{ # Check whether lists are different
  $Difference = Compare-Object -ReferenceObject $DomainsToBlock -DifferenceObject $ActiveKeywords
  $DiffCount = ($Difference | Measure-Object).Count

  if($DiffCount -gt 0)
  {
    write-host "$DiffCount keyword changes. Recreating keywords and firewall rule..."
    Get-NetFirewallRule -DisplayName $RuleName -ErrorAction Ignore | Remove-NetFirewallRule -Verbose
    Get-NetFirewallDynamicKeywordAddress -PolicyStore PersistentStore -ErrorAction Ignore | Remove-NetFirewallDynamicKeywordAddress -Verbose
  
    $NewKeywordIDs = Refresh-DomainKeywords($DomainsToBlock)
    
    write-host "Keyword IDs:"
    $NewKeywordIDs

    $nf = New-NetFirewallRule -DisplayName $RuleName -PolicyStore PersistentStore -Profile Any -Direction Outbound -Action Block -RemoteDynamicKeywordAddresses $NewKeywordIDs -Verbose
    write-host "New firewall rule created. $($nf.Name) - $RuleName"
  }
  else
  {
    write-host "No changes required."
  }
}


