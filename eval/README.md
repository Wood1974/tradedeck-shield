# Labelling job photos for the AI evaluation

This is how you tell Shield what is truly in a set of your own photos, so an AI's findings can be scored against your answers (`docs/features/inspection-eval.md`). Nothing here calls an AI, and nothing is uploaded: the converter reads your spreadsheet and your photo folder on your own computer.

## 1. Make the sheet

Open `eval/labels_template.csv` in Excel, Numbers or Google Sheets. Row 1 is the header; **one row per photo** below it.

| Column | What to put |
|---|---|
| `photo_file` | The file name of the **original** photo, exactly as it is in your photo folder (for example `IMG_4021.jpg`). Not a screenshot or a copy sent by text message: the converter fingerprints the file, and a re-saved copy is a different file. |
| `checkpoint` | Where in the job it was taken, for example `pre-pour`. Optional, but fill it in for any photo where a step could be missing. |
| `conditions` | Anything that could change how hard the photo is, separated by semicolons: `concrete;daylight`, `framing;low-light`. Optional. Results are reported per condition, so be consistent. |
| `material:...`, `missing-step:...`, `defect:...` | Put `x` if it is **truly present** in the photo. Leave blank if not. Nothing else: `y`, `yes` and `1` are refused so a typo is not silently counted as "no". |

How to decide what is present:
- **material:** the material is clearly visible in the photo.
- **defect:** you would write it up if you saw it on site.
- **missing-step:** `x` means the step is expected at this checkpoint **and is not done** in the photo. Leave it blank both when the step is done and when it is not expected here.
- Label only what the photo shows. If you cannot tell from the photo, leave it blank; do not use what you remember about the site.
- Include photos with nothing wrong, and photos taken in poor light. Only easy, clean photos would flatter the result.

The columns that ship are **placeholders**. They are your trades, not mine: add, rename or delete label columns to match your work. A label column is `category:label`, lowercase, no spaces (`material:pvc-pipe`). The three categories must each keep at least one column.

## 2. Keep these photos separate

Put the photos you label in their own folder, apart from real job records. Do not label photos with people's faces or licence plates in them if you can avoid it.

## 3. Convert

Save the sheet as CSV, then from the repo root:

```
python eval/csv_to_set.py labels.csv --photos /path/to/photo/folder --out eval_set.json
```

It writes `eval_set.json` (what the scorer reads) and `eval_set.json.files.json` (which case is which photo, so a wrong answer in a run can be traced to a file). It refuses, and names the row for: a typo in an `x` cell, a missing file, the same file twice (even under two names), an unknown column. It warns, without stopping, about labels with few examples.

## 4. How many photos

This is arithmetic, not a promise. A rate measured on few examples has a wide margin: a perfect 40 out of 40 still only supports "at least about 91%". Each label needs its own examples, and the label's *present* photos are what count for recall. So **more photos showing each thing you care about** helps more than more labels. About 100 photos, spread across many labels, will give wide intervals on most of them; the scorer prints those intervals rather than hiding them, and calls a category "not validated" unless the margin clears the pass bar you set.

## 5. Score a model (later)

`python -m app.inspection_eval eval_set.json submission.json` (from `server/`) scores a model's answers. There is no live model call yet; see `docs/features/inspection-eval.md`.
