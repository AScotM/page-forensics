# Page Forensics

A Linux virtual-memory investigation CLI written in Go using only the standard library. Single-file implementation, GPLv3.

## Features

- Inspect `/proc/meminfo` and `/proc/vmstat` without requiring root.
- Inspect per-node and per-zone buddy allocator free lists from `/proc/buddyinfo`.
- Calculate free pages and the largest available order per zone.
- Read memory pressure stall information (PSI) and transparent huge-page policy.
- Emit colored terminal reports, JSON snapshots, and CSV metric inventories.
- Monitor continuously or for a specified number of samples.
- Compare monotonic VM counters with the preceding sample or a saved baseline.
- Read fixtures from an alternate root for repeatable tests.

## Build

```sh
go build -o page-forensics .
```

## Examples

```sh
./page-forensics
./page-forensics -no-color
./page-forensics -interval 2s -count 10 -clear
./page-forensics -interval 1s -count 0
./page-forensics -output reports/initial
./page-forensics -baseline reports/initial.json
./page-forensics -json | python3 -m json.tool
./page-forensics -root ./fixtures
```

`-output` creates `.json` and `.csv` files. For multiple samples, a numeric suffix is inserted. `-json` prints one JSON object per sample to stdout.

## Interpretation and limitations

- `MemAvailable` is a kernel estimate, not a guarantee of immediately allocatable memory.
- `/proc/vmstat` values are a mix of event counters and gauges. Deltas are only meaningful for monotonic counters, and counter reset or rollover cannot be distinguished from a restart.
- `/proc/buddyinfo` free lists are instantaneous snapshots. High-order allocation failures cannot be inferred from the largest currently available order alone.
- `fragmentation_index` in the JSON zone structure is an illustrative size ratio, **not** the kernel's extfrag index. Do not interpret it as an allocation failure probability.
- PSI averages are percentages of wall-clock time stalled over their named windows; `total` is in microseconds.
- Some kernel counters and sysfs files are absent or renamed across distributions and kernel versions. Missing optional files are tolerated.
- `MemInfo` values are mostly KiB but certain counters in `/proc/meminfo` are not KiB; consult kernel documentation for each field.
- This program reads kernel interfaces and does not alter VM tunables.

## Security

The program is read-only. Avoid treating `/proc` values as immutable during collection. Exported reports can reveal hostnames and configuration details; review before publishing.

## License

GPL-3.0-or-later. See LICENSE.
