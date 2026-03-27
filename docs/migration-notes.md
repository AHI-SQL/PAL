# Migration Notes

## Direction retenue

La modernisation demarre sur une base Python avec interface web locale.
Cette premiere etape ne reecrit pas encore le moteur historique `PAL.ps1`, mais elle deplace deja le centre du projet vers :

- une base de code Python lisible et testable
- une exposition structuree des fichiers XML de seuils
- une interface moderne orientee exploration et migration

## Pourquoi cette etape d'abord

Le code historique melange trois couches :

- GUI WinForms en VB.NET
- moteur d'analyse PowerShell
- regles metier encodees dans les XML de seuils

Avant de remplacer completement le moteur, il faut rendre ces donnees visibles et manipulables dans une architecture plus claire.

## Ce qui a ete pose

- `backend/` : API Python locale et parseur de fichiers de seuils
- `frontend/` : nouvelle interface web locale
- `resources/thresholds/` : copie des fichiers XML reutilisables

## Prochaine etape logique

- parser aussi les scripts PowerShell herites pour cartographier les fonctions a reimplementer
- importer les logs `.blg` et `.csv`
- construire un moteur Python pour executer les regles aujourd'hui ecrites en PowerShell

