# Cost fixtures

- `azure-focus-1.0-ea-sample.csv`: header and first six rows of Microsoft's
  published FOCUS 1.0 sample (`microsoft/finops-toolkit`,
  `src/open-data/dataset-examples/EA-Cost-FOCUS_1.0.csv`, MIT licence),
  byte for byte, BOM and CRLF included.
- `gcp-focus-*.csv`: Google publishes no sample; built from the column list
  of the FOCUS BigQuery table, exported to CSV as BigQuery writes
  timestamps (`… UTC`) with `x_Tags` flattened to JSON in the export query.
- `alibaba-bill-*.csv`: the new-version standard detailed bill's path-style
  headers from Alibaba's field description; values invented.
- `alibaba-focus-preview-*.csv`: the invitation-only FOCUS 1.0 preview
  (`X_` extension columns).
- `aws-*`, `tencent-*`: earlier milestones.
