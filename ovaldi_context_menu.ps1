# PowerShell script to create registry keys for OVALDI context menu.

$a = Test-Path -path registry::HKEY_CURRENT_USER\Software\Classes\xmlfile

if ( $a -eq "True")
	{ 
		Write-Host "Key Exists"

	}
	else
	{	
	# Create the hives and paths
		New-Item -Path registry::HKEY_CURRENT_USER\Software\Classes\xmlfile
		New-Item -Path registry::HKEY_CURRENT_USER\Software\Classes\xmlfile\shell
		New-Item -Path registry::HKEY_CURRENT_USER\Software\Classes\xmlfile\shell\runOVAL
		New-Item -Path registry::HKEY_CURRENT_USER\Software\Classes\xmlfile\shell\runOVAL\Command
		Set-ItemProperty -Path registry::HKEY_CURRENT_USER\Software\Classes\xmlfile\shell\runOVAL\Command -Name'(Default)' -Type String -Value '"C:\Program Files\OVAL\ovaldi-5.10.1.6-x64\ovaldi.exe" -m -a "C:\Program Files\OVAL\ovaldi-5.10.1.4-x64\xml" -o %1 -p -k'
        Write-Host "Hives and Keys created"
	}

# Used to undo/delete the hive
# Remove-Item -Path registry::HKEY_CURRENT_USER\Software\Classes\xmlfile -Recurse

