# Script pour renommer les fichiers images en supprimant les espaces
$folderPath = "c:\Users\Aoudia Nour Islam\OneDrive\Desktop\TP-Snort-IDS"

# Extensions d'images à traiter
$imageExtensions = @("*.png", "*.jpg", "*.jpeg", "*.gif")

# Créer un tableau pour stocker les mappages ancien nom -> nouveau nom
$renameMappings = @()

foreach ($extension in $imageExtensions) {
    $images = Get-ChildItem -Path $folderPath -Filter $extension -File
    
    foreach ($image in $images) {
        $oldName = $image.Name
        $newName = $oldName -replace ' ', '-'
        
        if ($oldName -ne $newName) {
            $oldPath = $image.FullName
            $newPath = Join-Path $folderPath $newName
            
            # Vérifier si le nouveau nom existe déjà
            if (Test-Path $newPath) {
                Write-Host "AVERTISSEMENT: Le fichier '$newName' existe déjà. Ignoré." -ForegroundColor Yellow
            } else {
                # Renommer le fichier
                Rename-Item -Path $oldPath -NewName $newName
                Write-Host "Renommé: '$oldName' -> '$newName'" -ForegroundColor Green
                
                # Stocker le mappage pour mise à jour du rapport
                $renameMappings += [PSCustomObject]@{
                    OldName = $oldName
                    NewName = $newName
                }
            }
        }
    }
}

# Afficher un résumé
Write-Host "`n=== RÉSUMÉ ===" -ForegroundColor Cyan
Write-Host "Nombre de fichiers renommés: $($renameMappings.Count)" -ForegroundColor Cyan

if ($renameMappings.Count -gt 0) {
    Write-Host "`nMaintenant, vous devez mettre à jour les références dans report-v1.md" -ForegroundColor Yellow
    Write-Host "Mappages à appliquer:" -ForegroundColor Yellow
    $renameMappings | Format-Table -AutoSize
}
