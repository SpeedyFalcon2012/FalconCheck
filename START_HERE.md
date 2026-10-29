# Falcon Check 0.9

Falcon Check combines three jobs: a local ClamAV malware check, selected source
and executable clues, and explanations of what those results mean. It does not
prove safety. A file selected for scanning is never run, modified, or uploaded.

## Update from 0.6, 0.7, or 0.8 while keeping your version folders

1. Create your `FalconCheckV0.9` folder inside your usual Falcon Check folder.
2. Save `falcon-check-v0.9.tar.gz` there. You may also extract it there to keep
   a browsable source copy, but the updater does not require extraction.
3. In Falcon Check 0.6, 0.7, or 0.8, click **Install update…**, choose the archive, and install.
4. Click **Restart now**. Check that the title says **Falcon Check 0.9**.

Your collection of version folders is untouched. The menu app uses its own
copy under `~/.local/share/falcon-check/releases/`. Older installed versions are
retained; no automatic cleanup or rollback button is provided. The menu switches
only after all required new files have been copied. App updates are local:
there is no automatic download or signed-release update server. The package
manifest detects damaged/inconsistent files, not publisher identity. Install
Falcon Check updates only from a source you trust.

If you are installing for the first time, or are still on 0.5, extract the
archive and run **Setup-Falcon-Check.sh**. If the file manager opens it in an
editor, open a terminal in the extracted folder and run:

```bash
python3 install_launcher.py
```

This setup needs no administrator password, sudo, or network connection.
It creates `~/.local/share/applications/falcon-check.desktop` for your account.
An absolute `XDG_DATA_HOME` setting changes the base directory. It protects
unrelated app folders/menu entries. Editing extracted source files does not
change the menu app automatically. This is a user-local Python app, not an AppImage.

To launch the extracted copy directly, use **Start-Falcon-Check.sh** or
`python3 falcon_check.py --gui`. Python 3.8+ and Tkinter are needed for the
window; the CLI does not require Tkinter. Built-in analysis uses the standard
library. Terminal-only installation is `python3 install_launcher.py --cli`.

The updater accepts packages up to 8 MiB compressed/expanded, 1 MiB per member,
and 64 entries. It rejects unsafe paths, archive links, duplicates, missing or
changed files, and same/older versions. Future Python modules listed in the
manifest are supported by the 0.6 updater.

## New in 0.9: broader tracing and clearer evidence

Python analysis now follows more supported ways of constructing a sensitive
path and passing its contents to an upload:

- F-strings whose interpolated values are known strings. No source expressions
  are executed. Simple string conversions are supported; format specifications,
  numeric/object interpolation, and unknown values remain unsupported.
- Imported `os.path.join` and `posixpath.join`, including selected aliases.
  Absolute components correctly discard earlier components. Joining is lexical;
  it does not resolve symlinks, inspect the referenced path, or expand home or
  environment variables. `os.path` uses the scanner's operating-system rules.
- `pathlib.Path` with known components, `/`, `joinpath`, `read_text`, `read_bytes`,
  and readable `Path.open` handles. Native Path semantics follow the scanner's
  operating system; explicit WindowsPath/PureWindowsPath analysis is not added.
- Direct Requests uploads and `post`, `put`, and `patch` on a locally constructed
  Requests Session, including selected instance/method aliases and `with` blocks.

Reports in both the app and terminal now label **Source fact**, **Inferred
connection**, **Possible legitimate use**, and **Suggested action**. A backup
comment or familiar destination does not silently suppress evidence: the
scanner cannot establish who authorized a transfer. Conversely, an unrelated
status upload is not connected to a sensitive read merely because they appear
in the same file.

Use **Try demo** to see the new report. The updated **evidence-demo.txt** combines
an f-string, path joining, and a Session upload in a function that is never called.
For the complete scan/preview/save workflow, follow the steps below. Requests
need not be installed because the sample is parsed as text, never imported.

The developer fixture collection **tracing-examples.json** contains eight inert
examples and their expected upload-finding counts. It includes an ordinary
upload, a possible authorized backup, unrelated operations, a reassigned payload,
and a deliberately unsupported unknown path. Zero expected upload findings is
not a statement that an example is safe. Tests inspect these source strings;
never run them to test the scanner.

This remains deliberately limited tracing. General `.request`, `.send`, GET
methods, session defaults, user-defined HTTP wrappers, global session state
across functions, data transformations, and other HTTP libraries are not added.
Unpacked upload arguments (`*args`/`**kwargs`) are left for manual analysis.
Conflicting branches and selected mutations discard assumptions, which can
cause missed flows. No new scan mode or additional dependency is required.
Executable, archive, and antivirus coverage is unchanged in this release.

## Evidence and a proposed source fix

Falcon Check supports one specific evidence-and-fix case: a supported Python file read feeding an
HTTP upload. It reports the sensitive path, line-by-line value trace, upload
call, and destination when known. The finding means a possible source-code
flow, not proven malicious intent or observed transmission. Deliberate backups
can be legitimate. No code in the selected file is imported or run.

Try it without installing Requests or antivirus:

1. Extract the release archive in your `FalconCheckV0.9` folder.
2. In the app, Browse to **evidence-demo.txt** in the extracted folder.
3. Select **Python syntax** and Scan. The example is stored as text and its
   function is never called. Do not run the example.
4. Read **Potential sensitive-file upload**, its trace, destination and uncertainty.
5. Click **Preview fix…**. If several eligible calls exist, select one.
6. Read the before/after diff and consequence. **Approve & save separate copy…**
   asks you for a new filename, writes the copy and rechecks it.

Try demo also shows this evidence in memory. Its Preview fix button stays
unavailable because there is no source file to save from; use the fixture above
for the full workflow. Ordinary `.py` files get this analysis in Recommended
scan, Automatic (built-in), or Python syntax. The `.txt` fixture requires
explicit Python syntax mode.

The proposed change replaces one entire standalone upload call with `pass`
and an explanatory comment. That also removes evaluation of the call's
arguments and can break an intended upload/backup feature. Earlier reads and
other calls remain. Calls assigned to a variable, returned, nested in another
expression, or sharing a line with other statements require manual review;
no automatic patch is offered for them.

Previewing writes nothing. Saving never overwrites the original or an existing
output path. A changed source invalidates the preview. A new copy has private
read/write permissions and is not marked executable. The copy is rechecked with
the same limited Python analyzer; it is not executed or antivirus-scanned by
the patch workflow. Remaining findings stay visible. Losing one finding does
not prove a program safe or repaired, and this is not a general malware cleaner.

Supported starting points: readable `open`, `io.open`, `builtins.open` handles,
selected `read`/`readline`/`readlines` calls, and the supported `pathlib.Path`
reads and path-building operations described above.
Supported upload calls: imported `requests.post`, `requests.put` and
`requests.patch`, and their supported Session equivalents, including selected
aliases, with data/json/files/params values.
Simple literals, assignments, lists/tuples and dictionaries can connect them.
The existing sensitive-path patterns select the sources; they do not recognize
every secret location. A container trace shows only its first recognized source.
At most 20 upload findings are reported; exceeding that budget stops analysis
with an incomplete result. Each other Python rule keeps its first finding.

This does not model arbitrary transformations, unsupported Session methods, other HTTP
libraries, cross-function flows, actual authorization, dependency identity,
network success, or runtime reachability. Container mutations/unknown uses
conservatively discard potentially aliased values and can cause missed flows.
The prior Python limits and approximations still apply. Executable and archive
scans retain their previous coverage; this feature does not repair compiled
programs such as the Minecraft launcher.

## First-time antivirus setup on your Mint laptop

Open **Antivirus setup…**:

1. **Check readiness** checks for an existing engine and tries a harmless scan.
2. If missing, **Download/setup engine** downloads the selected official ClamAV
   1.4.6 x86-64 Linux package (about 90 MiB) and verifies its exact SHA-256 before
   unpacking it into your own account. A mismatch stops setup.
3. **Download/update signatures** runs FreshClam to fetch its official malware
   signature databases. Allow additional disk space and several minutes for
   the first download. Internet access is needed for these download actions.
4. **Check readiness** again. READY means the engine loaded its databases and
   successfully scanned harmless test text.
5. Return to the main window, choose your file, and use **Recommended scan**.

Setup uses `dpkg-deb --extract`, normally available on Linux Mint. It does not
use a system package installation, administrator password, system service,
firewall change, or scheduled job. Do not run Falcon Check as root or with sudo.
Private engine files and databases live separately from app releases at
`~/.local/share/falcon-check-antivirus/`, so app updates preserve them.
The private engine takes priority over one found on PATH. On other platforms,
use an administrator-provided ClamAV installation; built-in setup is Linux x86-64 only.

The engine package hash is pinned in falcon_antivirus.py. The development check
verified this exact package's Cisco Talos signature. Falcon Check itself checks
the pinned SHA-256 when downloading; it does not dynamically import a new signing
key or accept a different package. A newer engine package/hash will need a newer
Falcon Check release. The separate Falcon Check app updater does not provide
this same publisher-authentication guarantee.

Use **Download/update signatures** regularly; this release does not update in
the background. With a system-managed ClamAV, signature updates stay with its
administrator. Setup/download failures appear as errors, never as readiness.
If FreshClam reports rate limiting, wait until its stated retry time; repeated
clicks will not fix it. Network failures or an unsupported laptop/library setup
may still need troubleshooting. Selected scan files are never uploaded.

## What Recommended scan means

Recommended scan is now the default in both the window and the CLI. It requests:

- Built-in inspection selected by file type.
- A local ClamAV malware scan, if the engine and signatures are usable.

The report lists the outcome of each separately. A missing/erroring antivirus
check makes the overall result incomplete unless there is a finding to review.
A built-in clue still says NEEDS REVIEW even when ClamAV reports no threats.
An antivirus detection takes precedence as THREAT REPORTED. No threat reported
is not a guarantee; the database, supported formats, and resource limits matter.

The individual modes are still useful for investigating something quickly.
They explicitly show when a malware scan was not requested.

## Analysis modes

| Mode | What it does |
| --- | --- |
| Recommended scan | Runs automatic built-in inspection and a local ClamAV check; missing/failed checks stay visible. |
| Automatic (built-in) | Chooses Python, text, executable inspection, archive inventory, or basic details from the header and filename. It does not automatically run ClamAV. |
| Python syntax | Checks selected calls and traces simple values through assignments, aliases, string concatenation, command lists, and supported sensitive-file upload flows. UTF-8 Python, up to 2 MiB. |
| Text patterns | Streams UTF-8 text through seven checks. The old 2 MiB input limit is removed. |
| File details | Computes whole-file SHA-256 and identifies selected headers, including ELF/Linux and PE/Windows executable information. |
| Executable inspection | Checks selected ELF program headers or PE sections, plus embedded ASCII string patterns and informational URL text. |
| Archive inventory | Lists metadata for ZIP/JAR, TAR/TAR.GZ, and Debian/ar packages, with selected entry-name checks. |
| Antivirus (ClamAV) | Uses an existing clamscan installation and its signature database. |

Large files are read in chunks. Whole-file hashing has no configured input-size
cap, but takes time proportional to size. Analysis budgets remain separate.
SHA-256 is a fingerprint, not a malware reputation lookup or proof of safety.

For the Minecraft launcher, use Recommended scan after antivirus setup.
Use Executable inspection for the built-in clues alone. ELF and PE
candidates now receive structure and string checks. A supported package still
gets an archive inventory. BASIC INSPECTION means no selected executable clue
matched within the stated coverage; NEEDS REVIEW means a clue matched, not that
malware was identified. Malformed/over-budget checks report partial coverage.
AppImage bundled files are not unpacked or inspected individually. Recommended scan includes the antivirus request; the standalone Antivirus mode
requests only that part.

Executable inspection reports:

- ELF program-header count, entry address, load segments, requested interpreter,
  and whether the last GNU stack header requests execution. Selected clues:
  writable-and-executable load segments and an executable stack request.
- PE32/PE32+ layout and section names; selected clue: a section requesting both
  write and execute access. Selected truncated/out-of-bounds tables are reported.
- Matches to the seven existing text patterns in printable ASCII byte runs,
  with byte offsets. These can be documentation, unused text, or ordinary program
  features. For example, the Python interpreter can legitimately contain eval text.
- Up to 12 distinct URL text examples, as information only. They are not opened,
  contacted, reputation-checked, or treated as suspicious merely for existing.

These checks describe evidence in a file. They do not tell us what it will do
when run, and they cannot certify it as safe.

## Window behavior

Browse retains the Zenity GTK picker when available, with a Tk fallback. Paste
literal paths without shell quotes. Ctrl+O opens Browse; Enter starts a scan.

The progress strip appears only during a scan. Its percentage covers file
reading; subsequent parser/antivirus work uses an activity animation. Cancel
stops an active scan. Large files are processed in a background thread.
Changing the path or mode clears the previous result. Copy report copies only
when clicked. Try demo analyzes harmless source text without executing it.

## Python analysis: what improved

Previously this could be missed:

```python
base = "/etc/"
path = base + "shadow"
open(path)
```

Now Falcon Check can connect the literal pieces and assignments to the open()
call. The finding includes the traced value and source line steps. It does not
execute the example or establish that the operation would succeed.

It also follows selected import/callable aliases, simple True/False shell flags,
and literal command lists. It forgets values after unknown reassignment and
selected mutations, keeps function locals separate, respects many simple name
shadowing cases, and drops conflicting values after branches. Both branches
are inspected without deciding whether they will execute.

This remains a small abstract analyzer. It does not model arbitrary function
calls, values returned by functions, object behavior, dynamic imports, globals
changing over time, dependencies, or complete Python semantics. F-strings with
unknown values or format specifications, unsupported path operations, argument
unpacking, and complex control flow can be missed.
Unknown values do not prove harmlessness. Strings are limited to 4,096 characters; tracked
lists and path/f-string construction to 32 parts/4,096 characters total, and displayed assignment chains to eight prior
steps. A matching trace is evidence of selected source structure, not observed
runtime behavior. Methods, exceptions, closures and scopes remain approximate.

## Antivirus limits

This integration sets a 1 GiB input limit, 2 GiB total scan-size budget, 10,000
internal files, recursion depth 16, and a five-minute scan timeout. The installed
engine also has its own format support and limits. Encrypted-content and
limit-exceeded alerts mean incomplete inspection. Errors or zero scanned files
do not become a no-threat result. The report includes engine output and engine/
database version information when available. FreshClam updates have a separate
15-minute timeout. Readiness checks may take two minutes while loading databases.

No removal, quarantine, move, or repair operation is requested from ClamAV. It may use
its own temporary files. Downloads happen only through explicit setup/update
buttons or their CLI equivalents. Scanning itself does not contact the network.

## Results

| Result | Meaning |
| --- | --- |
| NEEDS REVIEW | A selected check matched; legitimate files can match. |
| NO INDICATORS FOUND | Selected Python/text checks completed without a match. |
| BASIC INSPECTION | Selected static information/checks only; no payload malware verdict. |
| PARTIAL INSPECTION | Analysis was limited or incomplete. Read coverage and notes. |
| NOT INSPECTED | The selected analysis could not complete; a fingerprint may still be available. |
| ANTIVIRUS UNAVAILABLE | External antivirus was not found. |
| THREAT REPORTED | ClamAV reported a detection. Review its output. |
| NO THREATS REPORTED | ClamAV reported no threats within its coverage. |
| CANCELLED | No completed analysis verdict. |

No result proves safety or maliciousness. This is not formal verification or a
full security product. The selected file is never imported, executed, modified,
or uploaded. Reading can update access time. The app launches its own parser
helper and, when selected, the installed antivirus. Parser isolation controls
resource use; it is not a security sandbox.

## Coverage and resource limits

- Python: 2 MiB source and 100,000 syntax nodes; up to 20 upload findings and
  the first finding per other rule. See
  the limited value tracking described above. Parsing uses the installed Python
  grammar. The analyzer is not a complete execution or scope model.
- Python/archive/executable helpers: 25-second wall timeout. On Linux helpers also request
  512 MiB address space and 15 CPU seconds. Limit failures are incomplete results.
- Text: UTF-8 only, first hit per rule, 1 MiB chunks with 4 KiB text overlap.
  Patterns spanning more than that overlap across chunks can be missed. Binary
  bytes or invalid UTF-8 encountered later make inspection incomplete.
- Executables: up to 4,096 ELF program headers or 96 PE sections. Selected
  structure checks only, not full format validation. ASCII string checks inspect
  the first 64 MiB using 64 KiB chunks and 4 KiB overlap. Whole-file hashing still
  covers the rest. UTF-16, compressed/encrypted strings, runtime-built strings,
  and patterns longer than the overlap across boundaries can be missed. Long URL
  examples may be truncated. No disassembly, behavioral analysis, dependency
  loading, digital-signature verification, or bundled-payload analysis.
- Archives: up to 10,000 entries; preview of the first 100 names. ZIP/JAR reads
  directory metadata without inspecting member contents or validating every
  member's integrity. TAR/TAR.GZ has a 64 MiB expanded-stream budget; a large
  member may stop inventory early. Helper time/memory limits also apply.
  No archive members are extracted to disk.
- Debian/ar: top-level members and Debian marker only. Nested data/control
  archives and install scripts are not inspected or run. Extended ar member-name
  formats are unsupported.
- Recognized PDFs, images, unsupported archives, and other binaries get basic
  details; no built-in payload analysis. Ordinary gzip that is not TAR cannot
  receive a complete archive inventory.
- One regular file per scan. On Linux final-component symlinks, devices, pipes,
  and folders are refused; parent-directory symlinks can be followed. Changed
  files get an incomplete result. Run as an ordinary user.

More complete Python analysis and folder scanning remain future work.

## Terminal commands

Keep the extracted files together. From that folder:

```bash
python3 falcon_check.py --demo
python3 falcon_check.py "/path/to/file"  # Recommended combined scan
python3 falcon_check.py --mode auto "/path/to/file"  # Built-in checks only
python3 falcon_check.py --mode executable "/path/to/launcher"
python3 falcon_check.py --mode details "/path/to/launcher"
python3 falcon_check.py --mode archive "/path/to/package.deb"
python3 falcon_check.py --mode text "/path/to/large-script.txt"
python3 falcon_check.py --mode python "/path/to/script.py"
python3 falcon_check.py --mode antivirus "/path/to/file"
```

Preview and optionally save a proposed source change:

```bash
python3 falcon_check.py --mode python evidence-demo.txt
python3 falcon_check.py --preview-fix evidence-demo.txt
python3 falcon_check.py --preview-fix evidence-demo.txt --save-fixed-copy evidence-demo.reviewed.txt
```

The last command displays the preview and requires you to type `SAVE` before
writing. An existing destination is refused. Optional `--finding-id` selects the
ID printed beside an eligible upload finding. Preview always uses Python mode;
its recheck does not request antivirus. Successful preview/save commands return
0 even when other findings remain; read the report.

Antivirus setup also has terminal equivalents (downloads are explicit):

```bash
python3 falcon_antivirus.py --check
python3 falcon_antivirus.py --install
python3 falcon_antivirus.py --update-signatures
```

Replace example paths with yours. Without a filename, the CLI prompts for one.
`--gui --mode details "/path/to/file"` preloads the window. The terminal does
not require Tkinter/display. Both interfaces use the same backend.

Exit codes: 0 no selected indicators/no threats reported or successful demo;
1 needs review/threat reported; 2 unavailable/not inspected/error; 3 basic/partial
inspection; 130 cancelled. Exit 0 is not a safety certificate.

## Editing and verification

Open the folder in VSCodium. falcon_check.py holds rules, syntax checks, and CLI;
falcon_engine.py handles streaming and optional antivirus; falcon_formats.py
handles headers/inventories; falcon_worker.py is the parser helper;
falcon_gui.py supplies the window. falcon_executable.py implements executable
checks; falcon_update.py handles local release updates. falcon_python.py adds
limited value tracking; falcon_explain.py builds explanations; falcon_antivirus.py
and falcon_av_window.py handle optional private engine setup.
falcon_remediate.py and falcon_fix_window.py provide the preview/separate-copy workflow.

```bash
python3 -m unittest
```

201 automated tests cover rule behavior, parser budgets, streaming boundaries,
large files, cancellation, archives, executable clues, installer updates,
malformed packages, failed installation, Python value tracking, combined result
handling, and antivirus setup failures. New evidence/fix tests cover connected
and unrelated uploads, shadowing, mutations, read-only previews, stale sources,
refused overwrites/symlinks, UTF-8 byte offsets, newline preservation, and
explicit approval before saving. The 0.9 tests add path-joining semantics,
known and unknown f-string values, Session identity and mutation, legitimate
usage examples, and the unchanged separate-copy patch guarantees.
A separate harmless 128 MiB fixture in
0.6 verified full hashing and explicit executable string limits.

A real ClamAV 1.4.6 engine was downloaded, checked against its official release
SHA-256 and Cisco Talos signature, and started from a private folder. Integration
tests used a custom harmless signature to verify both detection and no-detection
results through Falcon Check. That test does not validate detection against the
full official malware database. FreshClam could not complete in the restricted
development environment because its root user/group initialization was blocked.
The ordinary-user setup and official signature download still need validation
on your Mint laptop. GUI logic is tested headlessly; visual layout needs a
check on Mint as well.

No real malware is needed for development or testing.

References:

- https://docs.python.org/3/library/ast.html
- https://docs.python.org/3/library/zipfile.html
- https://docs.python.org/3/library/tarfile.html
- https://docs.clamav.net/manual/Usage/Scanning.html
- https://specifications.freedesktop.org/desktop-entry-spec/latest/

Executable format references:

- https://gabi.xinuos.com/elf/02-eheader.html
- https://gabi.xinuos.com/elf/08-pheader.html
- https://www.kernel.org/doc/html/v6.7/userspace-api/ELF.html
- https://learn.microsoft.com/en-us/windows/win32/debug/pe-format

ClamAV setup references:

- https://docs.clamav.net/manual/Installing.html
- https://docs.clamav.net/manual/Usage/Configuration.html
- https://github.com/Cisco-Talos/clamav/releases/tag/clamav-1.4.6

Evidence-flow references:

- https://requests.readthedocs.io/en/latest/api/
- https://requests.readthedocs.io/en/latest/user/quickstart/

Tracing references:

- https://requests.readthedocs.io/en/latest/_modules/requests/sessions/
- https://docs.python.org/3/library/os.path.html
- https://docs.python.org/3/library/pathlib.html
- https://docs.python.org/3/reference/lexical_analysis.html#f-strings
