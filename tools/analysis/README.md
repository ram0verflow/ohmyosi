# Analysis

Turns the captures into the report's tables and figures. Everything is written
to `dist/analysis/` (ignored; never commit captures or outputs).

```sh
make report                                        # dist/runs.csv
./ohmyosi -report dist/runs -eval-slack 0s    -report-csv dist/analysis/runs-slack0.csv
./ohmyosi -report dist/runs -eval-slack 500ms -report-csv dist/analysis/runs-slack500.csv
python3 tools/analysis/challenge_csv.py dist/challenge/<base> ...   # challenge.csv
python3 -m venv dist/analysis/.venv && dist/analysis/.venv/bin/pip install matplotlib
dist/analysis/.venv/bin/python tools/analysis/figures.py           # fig_*.png
```

`figures.py` plots only from CSVs and writes every plotted number to
`figures_numbers.csv`, to check against `make report`. `baselines.csv` holds the
published figures by hand; verify each against its paper before quoting.

## Hand-check

`handcheck_sample.py` draws 50 random flows where last-answer showed a name
other than the handshake name (ECH-outer flows excluded), seed 20261123:

```sh
for f in dist/runs/*parallel*.pcapng; do ./ohmyosi -eval $f -eval-json > dist/analysis/$(basename $f .pcapng).json; done
python3 tools/analysis/handcheck_sample.py dist/analysis/*parallel*.json > dist/analysis/handcheck.csv
```

Open each flow in Wireshark with its `flow_filter` (ClientHello, certificate)
and `dns_filter` (answers for that address), then fill `label` with one of
`real-error`, `coalescing`, `same-company-alias` and report the tool's
precision.
