$vms_cit = Get-SCVirtualMachine -VMMServer "phvmmcit" -All
$vm = $vms_cit | select * -First 1
$vm | clip

$vms_cit | select VirtualMachineState, state
$vms_cit | Export-Csv C:\temp\vmms_cit.csv

$demo = Get-SCVirtualMachine -VMMServer "phvmmcit" -Name "tvmdemo1"
$demo | clip



