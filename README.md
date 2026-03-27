# PAL Modern

PAL entre dans une phase de modernisation dans ce depot.
La base historique VB.NET et PowerShell est encore presente pour reference, mais le nouveau point d'entree du projet est maintenant une fondation Python avec interface web locale.

## Ce qui a change

- une nouvelle application Python dans `backend/`
- une nouvelle interface moderne dans `frontend/`
- une copie des fichiers XML de seuils dans `resources/thresholds/`
- une premiere API pour explorer les fichiers de seuils, leurs heritages et leurs analyses

## Lancer la nouvelle application

Depuis le dossier `PAL` :

```powershell
python .\backend\run_dev.py
```

Puis ouvre :

```text
http://127.0.0.1:8765
```

## Importer un log

Depuis l'interface web :

- clique sur `Choisir un fichier CSV ou BLG`
- selectionne un fichier `.csv` ou `.blg`
- clique sur `Importer`

Ce qui est deja supporte :

- `CSV` et `BLG` : import depuis la nouvelle interface
- lancement du moteur historique `PAL.ps1` avec le threshold file selectionne
- prise en compte des questions PAL et de leurs valeurs
- production du rapport HTML PAL complet dans `resources/reports/legacy/`

Les fichiers importes sont stockes temporairement dans `resources/uploads/`.
Les rapports HTML generes sont ecrits dans `resources/reports/`.

## Verifier le backend

```powershell
python -m unittest discover .\backend\tests
```

## Structure

```text
PAL/
  backend/
  frontend/
  resources/
  docs/
  PAL2/   # base historique a migrer progressivement
```

## Notes

- Le moteur historique d'analyse PowerShell n'est pas encore reecrit.
- La premiere etape de modernisation expose surtout le patrimoine metier pour preparer la migration complete.
- Les fichiers XML de seuils sont deja integres a la nouvelle base.
