# Pipeline Lab

A small local web app for building and testing Vector pipelines: **source -> steps -> destination**, with real event counts after every stage. It runs the real `vector` binary on your Mac. Nothing leaves your machine.

## Easiest: run it in Docker

You only need Docker (OrbStack works). Vector and LuaJIT are inside the image.

```bash
docker compose up -d --build     # first build takes a minute
```

Open <http://127.0.0.1:8790>. Stop it with `docker compose down`; update after changing code with `docker compose up -d --build` again.

- **Saved pipelines** live in `./pipelines` and **Save to file** output lands in `./output`, so both survive rebuilds.
- **Log files and serializers:** put them in `./data` and refer to them as `/data/yourfile` in the app (the container cannot see the rest of your Mac). A sample serializer is in `data/example_serializer.lua`.
- The port is published on `127.0.0.1` only. Do not change it to `0.0.0.0`: the app runs Vector and Lua code you give it, so it must not be reachable from the network.
- Another Vector version: `docker compose build --build-arg VECTOR_VERSION=0.61.0`.

## Or run it without Docker

### Set up (once)

1. Install Vector:

   ```bash
   brew trust vectordotdev/brew && brew tap vectordotdev/brew && brew install vector
   ```

2. Start the app (Python 3 only, no packages to install):

   ```bash
   cd pipeline-lab
   python3 server.py
   ```

3. Open <http://127.0.0.1:8790>. If the port is busy: `PORT=9000 python3 server.py`.

The app works without Vector installed (you can build pipelines), but Run and Validate need it.

## How to use it

- Click a box to edit it on the right. Click the **+** between boxes to add a step.
- **Sources**: sample log generator, a file (path or pasted text), or an HTTP listener.
- **Steps**: filter (VRL condition), remap (VRL), sample (1 of every N), dedupe (match fields). Use *Move earlier/later* to reorder.
- **Destinations**: dev/null (count only, nothing stored), print to screen, or save to `output/`.
- **Validate** asks real Vector to check the config, including your VRL. **Run pipeline** runs it and shows events in/out per stage, JSON volume in/out, and sample events at every stage. **View config** shows the generated Vector JSON config.
- **Save** stores a pipeline in `pipelines/`; click one in the left list to load it. Three starter pipelines are included.

## Testing a Lua serializer (the DPM way: source, then serializer)

1. Set the **Source** to *Raw record(s)* and paste a vendor event as JSON (one object, an array, or one per line). This is what a collector hands to the serializer.
2. Add a **Lua serializer** as the last step (the **+** after the last box, or it is already there in the default pipeline). Paste your serializer, or give a file path on your Mac (the file is re-read on every run, so you can edit it in your own editor and press Run again).
3. Press **Run**. The **Serializer: before / after** tab shows what the serializer *changed*, not a list of events:
   - **MOVED**: same value, new field name (`src_ip` -> `src_endpoint.ip`)
   - **TYPE CHANGED**: same value, different type (`"47046"` -> `47046`)
   - **CHANGED**, **NOT CARRIED** (dropped or transformed), **ADDED** (constants and derived fields)
   - **SAME / UNMAPPED / EMPTY** are hidden by default; click their chips to show them.
   - Switch to **OCSF output** or **Raw input** to see the whole record.
4. Above the diff are automatic checks per record: class/category/activity set, `type_uid = class_uid x 100 + activity_id`, `time` in epoch milliseconds, `metadata.version`, `metadata.product.*`, and `dataSource.*` present and mirroring `metadata.product.*`.
5. A **Console lint** box flags things the DPM console would likely reject (trailing `..` string continuation, `//` and other Lua 5.3 syntax, `$identifier`, apostrophes in comments, missing `dataSource.*`).

With only a Lua serializer after a raw record source, Vector is not used at all. You can also put a serializer after a generator, file or HTTP source and any Vector steps; then the serializer receives the events as Vector produced them (including fields Vector adds, like `timestamp` and `source_type`).

The serializer runs on your local LuaJIT, not inside the DPM runtime. `require('json')` and `require('log')` work; DPM-only modules (`hmac`, `codec`) do not. Matching in the diff is by value, so a transformed value (an ISO time turned into epoch milliseconds, `risk_level` turned into `severity_id`) shows as NOT CARRIED plus ADDED. Install LuaJIT with `brew install luajit` if the app says it cannot find Lua.

## Things worth knowing

- Counts and "volume" come from hidden tap files after each stage, so they are exact for the events you fed in. Volume is the size of each event as JSON, which includes fields Vector adds (timestamp, host, source type), so it is not the raw log size.
- Generator and file runs end when the input is used up. An HTTP run is stopped a few seconds after the body is sent, because listeners never exit on their own.
- A VRL step that fails on some events does not stop the run; those events pass through unchanged and the error appears in the *Vector log* tab.
- Linear pipelines only (one path). No branching or routing yet.
- The server only listens on 127.0.0.1 and rejects requests from other sites. The file source reads files you point it at, up to 20 MB. Saved output goes only into the `output/` folder.
- This is a look-alike for learning and testing. It is not the SentinelOne console and does not use its components or branding.
