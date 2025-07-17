# Importer le module Active Directory
Import-Module ActiveDirectory

# Fonction de log complète et autonome
function Write-Log {
    param (
        [string]$Message
    )

    $logFolder = "C:\Users\Administrateur\Documents\Import-ADUsers"
    if (-not (Test-Path -Path $logFolder)) {
        New-Item -ItemType Directory -Path $logFolder -Force | Out-Null
    }

    $logFile = Join-Path -Path $logFolder -ChildPath "Import-LocalUsers.log"
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
    $logLine = "$timestamp - $Message"

    Add-Content -Path $logFile -Value $logLine
    Write-Host $logLine
}

# Chemin du fichier CSV
$csvPath = "C:\Users\Administrateur\Documents\Utilisateurs.csv"

# Vérification du fichier CSV
if (-not (Test-Path $csvPath)) {
    Write-Log "Fichier CSV introuvable à l'emplacement : $csvPath. Script arrêté."
    return
}

# Définir le chemin de l’OU
$OU = "OU=Utilisateurs,DC=ad,DC=mondomaine,DC=com"

# Vérifier que l’OU existe
if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$OU'" -ErrorAction SilentlyContinue)) {
    Write-Log "L'OU spécifiée n'existe pas : $OU. Script arrêté."
    return
}

# Importer les utilisateurs du CSV
$utilisateurs = Import-Csv -Path $csvPath -Delimiter ";"

Write-Log "Début du script d'importation des utilisateurs"

# Compteurs pour les statistiques
$successCount = 0
$failureCount = 0

foreach ($user in $utilisateurs) {
    $prenom = $user.Prenom
    $nom = $user.Nom
    $noEmpl = $user.NoEmpl
    $admin = $user.Admin

    # Vérification des champs essentiels
    if ([string]::IsNullOrWhiteSpace($prenom) -or [string]::IsNullOrWhiteSpace($nom) -or [string]::IsNullOrWhiteSpace($noEmpl)) {
        Write-Log "Champs manquants pour une ligne du CSV. Utilisateur ignoré."
        $failureCount++
        continue
    }

    if ($prenom.Length -lt 1 -or $nom.Length -lt 4) {
        Write-Log "Nom ou prénom trop court pour créer un identifiant. Utilisateur ignoré."
        $failureCount++
        continue
    }

    $baseUsername = ($prenom.Substring(0,1) + $nom.Substring(0,4)).ToLower()
    $username = $baseUsername
    $counter = 1

    # Générer un identifiant unique
    while (Get-ADUser -Filter { SamAccountName -eq $username } -ErrorAction SilentlyContinue) {
        $username = "$baseUsername$counter"
        $counter++
    }

    $fullname = "$prenom $nom"
    $userPrincipalName = "$username@ad.mondomaine.com"

    # Mot de passe sécurisé avec complexité
    $randomPart = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 4 | ForEach-Object {[char]$_})
    $passwordString = ($nom.Substring(0,2).ToUpper() + $prenom.Substring(0,2).ToLower() + $randomPart + "!").Trim()
    $securepassword = ConvertTo-SecureString $passwordString -AsPlainText -Force

    Write-Log "Traitement de l'utilisateur : $fullname ($username)"

    try {
        Write-Log "Création de l'utilisateur $username"
        New-ADUser `
            -Name $fullname `
            -GivenName $prenom `
            -Surname $nom `
            -SamAccountName $username `
            -UserPrincipalName $userPrincipalName `
            -Path $OU `
            -AccountPassword $securepassword `
            -Enabled $true `
            -ChangePasswordAtLogon $true `
            -Description "Employé #$noEmpl"

        Write-Log "Utilisateur $username créé avec succès"
        $successCount++

        # Si l'utilisateur doit être admin
        if ($admin -eq "Oui") {
            $groupName = "Admins du domaine"
            $group = Get-ADGroup -Filter { Name -eq $groupName } -ErrorAction SilentlyContinue
            if ($group) {
                $isMember = Get-ADUser -Identity $username | Get-ADPrincipalGroupMembership | Where-Object { $_.Name -eq $groupName }
                if (-not $isMember) {
                    Add-ADGroupMember -Identity $groupName -Members $username
                    Write-Log "$username ajouté au groupe '$groupName'"
                } else {
                    Write-Log "$username est déjà membre du groupe '$groupName'"
                }
            } else {
                Write-Log "Groupe '$groupName' introuvable. Ajout au groupe impossible pour $username"
            }
        }

    } catch {
        Write-Log "Erreur lors de la création de $username : $($_.Exception.Message)"
        $failureCount++
    }
}

Write-Log "Fin du script d'importation"
Write-Log "Nombre total d'utilisateurs dans le fichier : $($utilisateurs.Count)"
Write-Log "Nombre d'utilisateurs créés avec succès : $successCount"
Write-Log "Nombre d'échecs : $failureCount"
