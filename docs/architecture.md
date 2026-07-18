# Architecture of bandit-triage

This document explains how the project is structured and how data flows
through it.

## Data flow (the two phases)

The tool works in two phases. **Training** happens once and produces the
model file. **Analysis** runs every time you want to triage a Bandit report.
Note that `features.py` is used in *both* phases — it is essential that
training and analysis turn data into numbers in exactly the same way,
otherwise the model would receive inconsistent input.

```mermaid
flowchart TD
    subgraph TRAIN["PHASE 1 — Training (once)"]
        A["data/labeled_findings.json<br/>20 hand-labeled examples"] --> B["features.py<br/>signals → numeric vector"]
        B --> C["train_classifier.py<br/>trains the model"]
        C --> D["model.json<br/>stores the learned weights"]
    end

    subgraph ANALYZE["PHASE 2 — Analysis (every run)"]
        E["Bandit JSON report<br/>bandit -r . -f json"] --> F["loader.py<br/>reads JSON → Finding objects"]
        F --> G["features.py<br/>same code as Phase 1"]
        G --> H["classifier.py<br/>predicts + explains"]
        D -.loaded.-> H
        H --> I["cli.py / web_ui.py<br/>re-ranked, explained list"]
    end
```

## How the files depend on each other

```mermaid
flowchart LR
    loader["loader.py<br/>reads the JSON"]
    features["features.py<br/>text → numbers"]
    classifier["classifier.py<br/>model + explanation"]
    train["train_classifier.py"]
    cli["cli.py"]
    web["web_ui.py"]

    loader --> features
    features --> classifier
    train --> loader
    train --> features
    train --> classifier
    cli --> loader
    cli --> features
    cli --> classifier
    web --> cli
```

## The files, one by one

- **`loader.py`** — reads a JSON file (from Bandit or from the training
  data) and turns each finding into a tidy `Finding` object with fields like
  `filename`, `code`, `test_id`, `issue_severity`, and `cwe_id`. It does
  nothing clever — it just makes the data easy for the other files to work
  with.
- **`features.py`** — the conceptual core. An ML model can't read "this is a
  test file" — only numbers. This file turns each `Finding` into a list of
  numeric signals: is Bandit's own confidence/severity high or low? Does the
  file path look like a test file? Does the flagged code contain a
  placeholder-like word? Does tainted external input appear nearby? Which
  Bandit rule fired? Every number is a clue a human reviewer would actually
  look for by hand.
- **`classifier.py`** — a small logistic regression model. Each feature gets
  an importance weight; the model adds them up (weighted) and produces a
  probability between 0 and 1 ("how likely is this a real issue?"). Because
  it's just "weight × value" summed, it can also report *which* feature
  drove a given prediction — that's the explanation.
- **`train_classifier.py`** — takes all the labeled examples, runs them
  through `features.py`, and adjusts the weights until the model's guesses
  match the known labels. Saves the result to `model.json`.
- **`cli.py`** and **`web_ui.py`** — the two interfaces. They do the same
  thing (load a report, triage it, show the re-ranked and explained
  results), one from the terminal and one in the browser. Both import the
  same logic, so they always agree.
