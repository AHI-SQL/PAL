# PAL Modern

PAL is entering a modernization phase in this repository.
The historical VB.NET and PowerShell codebase is still present for reference, but the new project entry point is now a Python foundation with a local web interface.

## What Has Changed

- a new Python application in `backend/`
- a new modern interface in `frontend/`
- a copy of the threshold XML files in `resources/thresholds/`
- an initial API to explore threshold files, their inheritance, and their analyses

## Run The New Application

From the `PAL` folder:

```powershell
python .\backend\run_dev.py
```

Then open:

```text
http://127.0.0.1:8765
```

## Import A Log

From the web interface:

- click `Choose a CSV or BLG file`
- select a `.csv` or `.blg` file
- click `Import`

What is already supported:

- `CSV` and `BLG`: import through the new interface
- launch of the legacy `PAL.ps1` engine with the selected threshold file
- support for PAL questions and their values
- generation of the full PAL HTML report in `resources/reports/legacy/`

Uploaded files are stored temporarily in `resources/uploads/`.
Generated HTML reports are written to `resources/reports/`.

## Verify The Backend

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
  PAL2/   # historical codebase to migrate progressively
```

## Notes

- The legacy PowerShell analysis engine has not been rewritten yet.
- The first modernization phase mainly exposes the business knowledge and assets to prepare the full migration.
- The threshold XML files are already integrated into the new foundation.
