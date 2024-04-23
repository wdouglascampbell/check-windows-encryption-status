<# : batch portion (begins PowerShell multi-line comment block)

::::::::::::::::::::::::::::::::::::::::::::
:: Elevate.cmd - Version 4
:: Automatically check & get admin rights
:: see "https://stackoverflow.com/a/12264592/1016343" for description
::::::::::::::::::::::::::::::::::::::::::::
 @echo off
 CLS
 ECHO.
 ECHO =============================
 ECHO Running Admin shell
 ECHO =============================

:init
 setlocal DisableDelayedExpansion
 set cmdInvoke=1
 set winSysFolder=System32
 set "batchPath=%~dpnx0"
 rem this works also from cmd shell, other than %~0
 for %%k in (%0) do set batchName=%%~nk
 set "vbsGetPrivileges=%temp%\OEgetPriv_%batchName%.vbs"
 setlocal EnableDelayedExpansion

:checkPrivileges
  NET FILE 1>NUL 2>NUL
  if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
  if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)
  ECHO.
  ECHO **************************************
  ECHO Invoking UAC for Privilege Escalation
  ECHO **************************************

  ECHO Set UAC = CreateObject^("Shell.Application"^) > "%vbsGetPrivileges%"
  ECHO args = "ELEV " >> "%vbsGetPrivileges%"
  ECHO For Each strArg in WScript.Arguments >> "%vbsGetPrivileges%"
  ECHO args = args ^& strArg ^& " "  >> "%vbsGetPrivileges%"
  ECHO Next >> "%vbsGetPrivileges%"
  
  if '%cmdInvoke%'=='1' goto InvokeCmd 

  ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%vbsGetPrivileges%"
  goto ExecElevation

:InvokeCmd
  ECHO args = "/c """ + "!batchPath!" + """ " + args >> "%vbsGetPrivileges%"
  ECHO UAC.ShellExecute "%SystemRoot%\%winSysFolder%\cmd.exe", args, "", "runas", 1 >> "%vbsGetPrivileges%"

:ExecElevation
 "%SystemRoot%\%winSysFolder%\WScript.exe" "%vbsGetPrivileges%" %*
 exit /B

:gotPrivileges
 setlocal & cd /d %~dp0
 if '%1'=='ELEV' (del "%vbsGetPrivileges%" 1>nul 2>nul  &  shift /1)

@echo off & setlocal
set "POWERSHELL_BAT_ARGS=%*"

powershell -noprofile -NoLogo "iex (${%~f0} | out-string)"
exit /b %errorlevel%

: end batch / begin PowerShell chimera #>


# check if running with Administrator privileges
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (! $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  (get-host).UI.RawUI.Foregroundcolor="DarkRed"
  write-host "`nWarning: This script must be run as an Administrator.`n"
  (get-host).UI.RawUI.Foregroundcolor="White"
  exit
}

 
# Check Device Encryption Status of Each Drive
function Get-DeviceEncryptionStatus {
	param (
		[string[]]$drives
	)
	
	$systemDrive = (Get-WmiObject Win32_OperatingSystem).SystemDrive
	$bFullyEncrypted = $TRUE
	
	foreach ($driveLetter in $drives) {
		if ($systemDrive -eq "${driveLetter}:") {
			$driveType = "system drive"
		} else {
			$driveType = "drive"
		}
		
		$drive = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftVolumeEncryption" -Class Win32_EncryptableVolume | Where-Object { $_.DriveLetter -eq "${driveLetter}:" }
		if ($drive) {
			$protectionStatus = $drive.ProtectionStatus
			if ($protectionStatus -eq 1) {
				Write-Host "Device Encryption is enabled and active on the ${driveType} (${driveLetter}:)."
			} else {
				$conversionStatus = $drive.conversionStatus
				switch ($conversionStatus)
				{
					0 { Write-Host "Device Encryption is not enabled on the ${driveType} (${driveLetter}:)."; break }
					1 { Write-Host "Device Encryption is not enabled on the ${driveType} (${driveLetter}:) but the drive conversion status is 'Fully Encrypted'."; break }
					2 { Write-Host "Device Encryption is not enabled on the ${driveType} (${driveLetter}:) but the drive conversion status is 'Encryption in Progress'."; break }
					3 { Write-Host "Device Encryption is not enabled on the ${driveType} (${driveLetter}:) and the drive conversion status is 'Decryption in Progress'."; break }
					4 { Write-Host "Device Encryption is not enabled on the ${driveType} (${driveLetter}:) but the drive conversion status is 'Encryption Paused'."; break }
					5 { Write-Host "Device Encryption is not enabled on the ${driveType} (${driveLetter}:) and the drive conversion status is 'Decryption Paused'."; break }
					Default { Write-Host "Device Encryption is not enabled on the ${driveType} (${driveLetter}:) but the drive conversion status is unknown."; break }
				}
				$bFullyEncrypted = $FALSE
			}
		}
	}
	
	return $bFullyEncrypted
}

function Display-Press-Any-Key {
	Write-Host ""
	Write-Host -NoNewLine "Press any key to continue..."
	$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Get-OS-Name {
	Write-Host ""
	Write-Host "Retrieving operating system information.  Please wait..."
	Write-Host ""

	# Get Operating System Name and Version
	$OriginalPref = $ProgressPreference # Default is 'Continue'
	$ProgressPreference = "SilentlyContinue"
	$computerInfo = Get-ComputerInfo OsName, OsVersion
	$ProgressPreference = $OriginalPref

	Write-Host "$($computerInfo.OsName) (Version $($computerInfo.OsVersion)) detected." -ForegroundColor yellow
	Write-Host ""
	
	Return $computerInfo.OsName
}

# Initialize encryption status
$bFullyEncrypted = $FALSE

# Check Device Encryption status for Windows Pro and Windows Home
if (Get-OS-Name -match "Windows 1(0|1) (Pro|Home)") {
	# Get list of drive letters of all non-removable drives
	$drives = (Get-PSDrive -PSProvider FileSystem).Name
    $removableDrives = Get-WmiObject -Class Win32_LogicalDisk | Where-Object {$_.DriveType -eq 2}
    if ($removableDrives -ne $NULL) {
    	$drives = [Array]($drives | Where-Object { $removableDrives.DeviceID.Trim(":") -notcontains $_ })
    }
	$bFullyEncrypted = Get-DeviceEncryptionStatus $drives
} else {
    Write-Host "Using an unsupported Windows version is not secure." -ForegroundColor red
	Display-Press-Any-Key
	exit
}

Write-Host ""
if ($bFullyEncrypted) {
	Write-Host "This system has Microsoft Device Encryption or Bitlocker enabled for all drives." -ForegroundColor green
	Display-Press-Any-Key
	exit
}

Write-Host "This system is NOT using Microsoft Device Encryption or Bitlocker for all drives."
Write-Host



# from Win10 SDK source: include/10.0.16299.0/km/d4drvif.h
# ========================================================
# #ifndef CTL_CODE
# 
# //
# // Macro definition for defining IOCTL and FSCTL function control codes.  Note
# // that function codes 0-2047 are reserved for Microsoft Corporation, and
# // 2048-4095 are reserved for customers.
# //
# 
# #define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
#     ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
# )
# 
# //
# // Define the method codes for how buffers are passed for I/O and FS controls
# //
# 
# #define METHOD_BUFFERED                 0
# #define METHOD_IN_DIRECT                1
# #define METHOD_OUT_DIRECT               2
# #define METHOD_NEITHER                  3
# 
# //
# // Define the access check value for any access
# //
# //
# // The FILE_READ_ACCESS and FILE_WRITE_ACCESS constants are also defined in
# // ntioapi.h as FILE_READ_DATA and FILE_WRITE_DATA. The values for these
# // constants *MUST* always be in sync.
# //
# 
# 
# #define FILE_ANY_ACCESS                 0
# #define FILE_READ_ACCESS          ( 0x0001 )    // file & pipe
# #define FILE_WRITE_ACCESS         ( 0x0002 )    // file & pipe
# 
# #endif
#
$METHOD_BUFFERED = 0
$FILE_ANY_ACCESS = 0

function CTL_CODE {
	param (
		$DeviceType,
		$Function,
		$Method,
		$Access
	)
	
	return (($DeviceType -shl 16) -bor ($Access -shl 14) -bor ($Function -shl 2) -bor $Method)
}

# from Win10 SDK source: include/10.0.16299.0/um/winioctl.h
# =========================================================
# #define FILE_DEVICE_UNKNOWN             0x00000022
$FILE_DEVICE_UNKNOWN = 34

# from VeraCrypt source: src/Common/Apidrv.h
# ==========================================
# #define TC_IOCTL(CODE) (CTL_CODE (FILE_DEVICE_UNKNOWN, 0x800 + (CODE), METHOD_BUFFERED, FILE_ANY_ACCESS))
#
function VC_IOCTL {
	param (
		$CODE
	)
	
	return CTL_CODE $FILE_DEVICE_UNKNOWN (0x800 + $CODE) $METHOD_BUFFERED $FILE_ANY_ACCESS
}
	
$NtFunctions=Add-Type -Name 'NtFunctions' -Namespace 'win32' -PassThru -MemberDefinition @"
    [DllImport("Kernel32.dll", SetLastError = true)]   
    public static extern bool DeviceIoControl(   
        IntPtr hDevice,   
        int IoControlCode,   
        byte[] InBuffer,   
        int nInBufferSize,   
        IntPtr OutBuffer,    
        int nOutBufferSize,    
        ref int pBytesReturned,    
        IntPtr Overlapped);

	[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
	public static extern IntPtr CreateFileW(
     [MarshalAs(UnmanagedType.LPWStr)] string filename,
     [MarshalAs(UnmanagedType.U4)] System.IO.FileAccess access,
     [MarshalAs(UnmanagedType.U4)] System.IO.FileShare share,
     IntPtr securityAttributes,
     [MarshalAs(UnmanagedType.U4)] System.IO.FileMode creationDisposition,
     [MarshalAs(UnmanagedType.U4)] System.IO.FileAttributes flagsAndAttributes,
     IntPtr templateFile);
"@

# Note:	Need to use /unsafe compiler parameter for C# code to allow defining fixed
#       sized arrays inside struct typedef.
$cp = New-Object System.CodeDom.Compiler.CompilerParameters
$cp.CompilerOptions = '/unsafe'
Add-Type -CompilerParameters $cp @'
	using System;
	using System.Runtime.InteropServices;

	[StructLayout(LayoutKind.Sequential, Pack=1)]
	public struct BootEncryptionStatus {
		// New fields must be added at the end of the structure to maintain compatibility with previous versions
		public System.Int32 DeviceFilterActive;

		public System.UInt16 BootLoaderVersion;

		public System.Int32 DriveMounted;
		public System.Int32 VolumeHeaderPresent;
		public System.Int32 DriveEncrypted;

		public System.Int64 BootDriveLength;

		public System.Int64 ConfiguredEncryptedAreaStart;
		public System.Int64 ConfiguredEncryptedAreaEnd;
		public System.Int64 EncryptedAreaStart;
		public System.Int64 EncryptedAreaEnd;

		public System.UInt32 VolumeHeaderSaltCrc32;

		public System.Int32 SetupInProgress;
		public System.Int32 SetupMode;
		public System.Int32 TransformWaitingForIdle;

		public System.UInt32 HibernationPreventionCount;

		public System.Int32 HiddenSystem;
		public System.Int64 HiddenSystemPartitionStart;

		// Number of times the filter driver answered that an unencrypted volume
		// is read-only (or mounted an outer/normal TrueCrypt volume as read only)
		public System.UInt32 HiddenSysLeakProtectionCount;
	}

	// from VeraCrypt source: src/Common/Crypto.h
	// ==========================================
	//#define SHA256_DIGESTSIZE			32
	//

	// from VeraCrypt source: src/Common/Common.h
	// ==========================================
	//#define VOLUME_ID_SIZE   SHA256_DIGESTSIZE
	//

	// from VeraCrypt source: src/Common/Tcdefs.h
	// ==========================================
	//#ifdef MAX_PATH
	//#define TC_MAX_PATH				MAX_PATH
	//#else
	//#define TC_MAX_PATH				260		/* Includes the null terminator */
	//#endif
	//

	// from VeraCrypt source: src/Common/Apidrv.h
	// ==========================================
	//typedef struct
	//{
	//	unsigned __int32 ulMountedDrives;	/* Bitfield of all mounted drive letters */
	//	wchar_t wszVolume[26][TC_MAX_PATH];	/* Volume names of mounted volumes */
	//	wchar_t wszLabel[26][33];	/* Labels of mounted volumes */
	//	wchar_t volumeID[26][VOLUME_ID_SIZE];	/* IDs of mounted volumes */
	//	unsigned __int64 diskLength[26];
	//	int ea[26];
	//	int volumeType[26];	/* Volume type (e.g. PROP_VOL_TYPE_OUTER, PROP_VOL_TYPE_OUTER_VOL_WRITE_PREVENTED, etc.) */
	//	BOOL reserved[26]; /* needed to keep the same size for the structure so that installer of new version can communicate with installed old version */
	//} MOUNT_LIST_STRUCT;
	//
	[StructLayout(LayoutKind.Sequential, Pack=1)]
	public unsafe struct MOUNT_LIST_STRUCT {
		public System.UInt32 ulMountedDrives;	/* Bitfield of all mounted drive letters */
		public fixed System.UInt16 wszVolume[6760];	/* Volume names of mounted volumes */
		public fixed System.UInt16 wszLabel[26*33];	/* Labels of mounted volumes */
		public fixed System.UInt16 volumeID[26*32];	/* IDs of mounted volumes */
		public fixed System.UInt64 diskLength[26];
		public fixed System.Int32 ea[26];
		public fixed System.Int32 volumeType[26];	/* Volume type (e.g. PROP_VOL_TYPE_OUTER, PROP_VOL_TYPE_OUTER_VOL_WRITE_PREVENTED, etc.) */
		public fixed System.Int32 reserved[26]; /* needed to keep the same size for the structure so that installer of new version can communicate with installed old version */
	}
'@

# for use with CreateFileW Win32 API Function
$INVALID_HANDLE_VALUE = -1
$ERROR_FILE_NOT_FOUND = 2

# from VeraCrypt source: src/Common/Apidrvr.h
# ===========================================
# // Get list of all mounted volumes
# // IN OUT - MOUNT_LIST_STRUCT (only 26 volumes possible)
# #define TC_IOCTL_GET_MOUNTED_VOLUMES					TC_IOCTL (6)
#
# #define TC_IOCTL_GET_BOOT_ENCRYPTION_STATUS				TC_IOCTL (18)
#
$VC_IOCTL_GET_MOUNTED_VOLUMES = VC_IOCTL 6
$VC_IOCTL_GET_BOOT_ENCRYPTION_STATUS = VC_IOCTL 18


# Check if VeraCrypt is installed
$bEncryptedWithVeraCrypt = $FALSE
if ([Boolean](get-package | Where-Object {$_.Name -match "VeraCrypt"})) {
	# Check if system is encrypted using VeraCrypt
	$VERACRYPT_DRIVER_STR = '\\.\VeraCrypt'
	$OPEN_EXISTING = 3
	$sFilePath = $VERACRYPT_DRIVER_STR
	$iAccess = 0
	$iShare = 0
	$tSecurity = 0
	$iCreation = $OPEN_EXISTING
	$iFlagsAndAttributes = 0
	$hTemplate = 0
	$hDriver = $NtFunctions::CreateFileW($VERACRYPT_DRIVER_STR, $iAccess, $iShare, $tSecurity, $iCreation, $iFlagsAndAttributes, $hTemplate)
	if ($hDriver -eq $INVALID_HANDLE_VALUE) {
		$iErrorNum = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
		Switch ($iErrorNum) {
			2 { Write-Host "Error: VeraCrypt was not found" -ForegroundColor red; break; }
			default { Write-Host "Error: Unknown Error # ${iErrorNum}"; break; }
		}
	} else {
		$tSystemAttributes = New-Object BootEncryptionStatus
		$tSystemAttributesSize = [System.Runtime.InteropServices.Marshal]::SizeOf($tSystemAttributes)
		
		# create output buffer to hold a BootEncryptionStatus struct
		$OutBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($tSystemAttributesSize)
		
		$BytesReturned = 0
		
		$result = $NtFunctions::DeviceIoControl($hDriver, $VC_IOCTL_GET_BOOT_ENCRYPTION_STATUS, $NULL, 0, $OutBuffer, $tSystemAttributesSize, [ref]$BytesReturned, [System.IntPtr]::Zero)
		if ($result) {
			$tSystemAttributes=[System.Runtime.InteropServices.Marshal]::PtrToStructure($OutBuffer, [System.Type] $tSystemAttributes.GetType())
			$bSystemEncrypted = $tSystemAttributes.DriveEncrypted
			
			# Free previously allocated memory
			[System.Runtime.InteropServices.Marshal]::FreeHGlobal($OutBuffer)

			if ($bSystemEncrypted) {
				$bEncryptedWithVeraCrypt = $TRUE
				
				# determine encrypted system drive letter
				$oSystemDrive = (Get-WmiObject Win32_OperatingSystem).SystemDrive

				Write-Host "System drive (${oSystemDrive}) is encrypted using VeraCrypt."

				$aMountedDriveList = [System.Collections.ArrayList]@()

				$tMountList = New-Object MOUNT_LIST_STRUCT
				$tMountListSize = [System.Runtime.InteropServices.Marshal]::SizeOf($tMountList)

				# create output buffer to hold a MOUNT_LIST_STRUCT struct
				$OutBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($tMountListSize)

				$result = $NtFunctions::DeviceIoControl($hDriver, $VC_IOCTL_GET_MOUNTED_VOLUMES, $NULL, 0, $OutBuffer, $tMountListSize, [ref]$BytesReturned, [System.IntPtr]::Zero)
				if ($result) {
					$tMountList=[System.Runtime.InteropServices.Marshal]::PtrToStructure($OutBuffer, [System.Type] $tMountList.GetType())
					For ($i = 0; $i -lt 26; $i++) {
						If ($tMountList.ulMountedDrives -band (1 -shl $i)) {
							$index = $aMountedDriveList.Add([char]([byte][char]'A' + $i) + ":")
						}
					}
				}

				# Free previously allocated memory
				[System.Runtime.InteropServices.Marshal]::FreeHGlobal($OutBuffer)

				#$oAllDrives = (Get-PSDrive -PSProvider FileSystem).Name
				$oNonSystemDrives = Get-WmiObject -Class Win32_Volume | Where-Object {$_.DriveType -eq 3 -and $_.FileSystem -ne $NULL -and $_.DriveLetter -ne $NULL -and $_.DriveLetter -ne $oSystemDrive}

				$aDrivesRequiringEncryption = [System.Collections.ArrayList]@()
				$oNonSystemDrives | ForEach-Object {
					if ($aMountedDriveList -notcontains $_.DriveLetter) {
						$index = $aDrivesRequiringEncryption.Add($_.DriveLetter)
					} else {
						Write-Host "Drive $($_.DriveLetter) is encrypted using VeraCrypt."
					}
				}

				if ($aDrivesRequiringEncryption.count -eq 0) {
					$bFullyEncrypted = $TRUE
				} else {
					Write-Host
					Write-Host "The following drives do not appear to be encrypted:"
					Write-Host ($aDrivesRequiringEncryption -join "`n")
				}
			} else {
				Write-Host "This system is not encrypted with VeraCrypt."
			}
		} else {
			$iErrorNum = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			Write-Host "An unexpected error has occurred!  Error # ${iErrorNum}" - Foreground red
		}
	}
} else {
	Write-Host "VeraCrypt is not installed."
}

if ($bFullyEncrypted) {
	Write-Host
	Write-Host "This system is fully encrypted." -ForegroundColor green
} else {
	Write-Host
	if ($bEncryptedWithVeraCrypt) {
		# Encrypted using VeraCrypt but only partially
		Write-Host "This system is NOT fully encrypted." -ForegroundColor red
	} else {
		# Check if BestCrypt is installed
		if (-not [Boolean](get-package | Where-Object {$_.Name -match "Bestcrypt"})) {
			Write-Host "Bestcrypt is not installed."
			Write-Host
			Write-Host "This system is NOT encrypted." -ForegroundColor red
		} else {
			$p = Start-Process -FilePath "C:\Program Files (x86)\Jetico\BestCrypt Volume Encryption\bcfmgr.exe" -ArgumentList "-GetEncryptedVolumes" -Wait -NoNewWindow -PassThru
			$iEncryptedDrivesBitmask = $p.ExitCode
			$aEncryptedDriveList = [System.Collections.ArrayList]@()
			For ($i = 0; $i -lt 26; $i++) {
				If ($iEncryptedDrivesBitmask -band (1 -shl $i)) {
					$index = $aEncryptedDriveList.Add([char]([byte][char]'A' + $i) + ":")
				}
			}

			$aDrivesRequiringEncryption = [System.Collections.ArrayList]@()
			$oDrives = Get-WmiObject -Class Win32_Volume | Where-Object {$_.DriveType -eq 3 -and $_.FileSystem -ne $NULL -and $_.DriveLetter -ne $NULL}
			$oDrives | ForEach-Object {
				if ($aEncryptedDriveList -notcontains $_.DriveLetter) {
					$index = $aDrivesRequiringEncryption.Add($_.DriveLetter)
				} else {
					Write-Host "Drive $($_.DriveLetter) is encrypted using Bestcrypt."
				}
			}
	
			if ($aDrivesRequiringEncryption.count -eq 0) {
				Write-Host
				Write-Host "This system is fully encrypted." -ForegroundColor green
			} else {
				Write-Host
				Write-Host "The following drives do not appear to be encrypted:"
				Write-Host ($aDrivesRequiringEncryption -join "`n")

				Write-Host
				Write-Host "This system is NOT fully encrypted." -ForegroundColor red
			}
		}
	}
}

Display-Press-Any-Key
