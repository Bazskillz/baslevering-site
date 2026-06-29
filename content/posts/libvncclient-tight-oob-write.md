---
title: "A pre-auth heap overflow in libvncclient's Tight decoder"
date: 2026-05-29
draft: false
tags: ["vulnerability-research", "vnc", "memory-safety", "disclosure"]
summary: "GHSA-v9pm-47h4-jcq8 — a malicious VNC server can crash or take over any client built on libvncclient, default build, no auth. My first CVE, and why the client trusting the server is the whole problem."
ShowToc: true
TocOpen: false
---

## TL;DR

A bug in libvncclient's Tight compression decoding logic (`tight.c`) can crash — or even achieve RCE in — a VNC client when a server sends crafted compressed data. The server is the attacker: no authentication, default build, default settings.

- **Advisory:** GHSA-v9pm-47h4-jcq8
- **CVE:** CVE-2026-50538
- **Severity:** CVSS 3.1 = 8.8 (High) — `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`
- **Affected:** libvncclient 0.9.12 → master (0.9.15+)
- **Fix:** commit `6724d69`, merged to master 2026-05-29

## Why a VNC client bug matters

To understand why this bug matters we have to look at the problem a bit differently from the usual way we think of hacking in the traditional sense. When you think of VNC you picture an attacker attacking a server — like gaining access to someone's remote VNC instance from the outside. This bug flips the script.

Think of it like this: you are the **client** (viewing the remote machine from your device), and the remote computer is the **server**. If the client fully trusts what the server sends it, the server can trick the client into doing bad things. The server says: *"Here is a picture of the desktop, it's big and it's zipped up. Unzip it and put it on your screen."* A bad server can then send a "poisoned" package — the client unwraps it, gets overwhelmed, and it crashes (or worse…).

Anything that embeds libvncclient is in scope: downstream desktop viewers, and any service or tool that opens outbound VNC connections.

## The bug: libvncclient heap overflow

The vulnerability is found in `src/libvncclient/tight.c`'s `HandleTightBPP()`. During Tight's basic compression a zlib stream decompresses into framebuffer rows *before* validating the total row count.

```c
while (compressedLen > 0) {
    ...
    numRows = (bufferSize - zs->avail_out) / rowSize;
    filterFn(client, rx, ry + rowsProcessed, numRows);   /* writes to framebuffer */
    rowsProcessed += numRows;                             /* not validated here   */
    ...
}
if (rowsProcessed != rh) return FALSE;                    /* height check, too late */
```

The `filterFn` macros calculate the memory destination using `srcy = ry + rowsProcessed`. If a malicious zlib stream decompresses into more rows than the rectangle's declared height (`rh`), `srcy` walks past the end of the allocated framebuffer. The trailing `rowsProcessed != rh` check only fires *after* the heap overflow has already occurred.

**Aggravating factors:**

- **No interception:** the filter functions bypass the application's `GotBitmap` / `CheckRect` callbacks, so the host application cannot block the write.
- **Default vulnerability:** Tight encoding is enabled by default whenever libvncclient is built with zlib and JPEG support (the default CMake configuration).

## From crash to control

The heap overflow is highly exploitable because many VNC viewers (such as `SDLvncviewer.c`) map `client->frameBuffer` directly to their live application objects (for example, `sdl->pixels`).

- **The impact:** rather than hitting a quiet guard page and safely crashing, the overflow overwrites adjacent live heap memory with attacker-controlled bytes.
- **The vector:** in typical viewer layouts (SDL/GTK/Qt), the framebuffer sits next to application callback pointers. The overflow can silently overwrite these pointers, redirecting code execution under the default configuration.
- **Scoping:** while achieving precise code execution on modern PIE + ASLR systems requires a separate information leak to bypass memory randomization, standard memory corruption and Denial of Service (DoS) work out of the box without any extra primitives.

<pre class="ascii-art" style="line-height:1.25;overflow-x:auto"><code>        MEMORY MAP  —  FROM CRASH TO CONTROL

        client-&gt;frameBuffer          adjacent live heap
        (16x16x4 = 1024 bytes)       (sdl-&gt;pixels, callback ptrs, app data)
        +----------------------+     +----------------------------+
NORMAL  |######################|     |  . . . untouched . . . .   |
write   |  stops at declared   |     |                            |
        |   height (rh rows)   |     |                            |
        +----------------------+     +----------------------------+

        +----------------------+-----+----------------------------+
PWNED   |#####################################################X###|
write   | decompressed rows &gt; rh  --  write runs off the end ---&gt; |
        +----------------------+-----+----------------------------+
                                                             ^
                                                             |  callback ptr
                                                             |  overwritten
                                                             v  exec hijacked

   DoS / memory corruption : guaranteed, default config.
   RCE                     : demonstrated; needs a leak to beat ASLR.</code></pre>

## Proving it

A minimal client using default callbacks, built with AddressSanitizer (ASan) on master (`5ea5fc30`), crashes immediately when connecting to a malicious server that sends a 16×16 Tight rectangle with an oversized zlib payload.

```text
ERROR: AddressSanitizer: heap-buffer-overflow ... WRITE of size 4
  #0 FilterCopy32            src/libvncclient/tight.c:400
  #1 HandleTight32           src/libvncclient/tight.c:344
  #2 HandleRFBServerMessage  src/libvncclient/rfbclient.c:2493

0x... is located 0 bytes after 1024-byte region   (16×16×4 bytes = the entire framebuffer)
allocated by ... MallocFrameBuffer  src/libvncclient/vncviewer.c:105
```

- **The root cause:** the output `0 bytes after 1024-byte region` confirms an immediate, precise overrun of the allocated framebuffer.
- **Reproducibility:** the vulnerability requires no complex tooling to trigger; it reproduces using a standalone malicious server script written in roughly 100 lines of Python.

## The fix

The vulnerability is patched by clamping the decompressed row count to the remaining rectangle height *inside* the processing loop, so before any writing occurs:

```c
numRows = (bufferSize - zs->avail_out) / rowSize;

if (numRows > rh - rowsProcessed) {
    rfbClientLog("Tight: too many scan lines after decompression.\n");
    return FALSE;
}

filterFn(client, rx, ry + rowsProcessed, numRows);
```

- **Consistency:** this 10-line patch aligns with existing bounds checking in the TRLE decoder (`trle.c`) and the Tight JPEG path, which already safely clamp to the rectangle height.
- **Verification:** post-patch, the proof-of-concept (PoC) is safely rejected with the log message, while valid Tight traffic continues to decode normally.
- **Distinct from commit `5b27054`:** do not confuse this with the recent "Tight gradient decoding overflow" fix. That patch addressed a width clamp on a stack buffer; this patch fixes a height / row-count overflow affecting the heap.

## Timeline

- **2026-05-24** — bug found, root-caused, and ASan / RCE PoCs built. Reported privately via GitHub Security Advisory.
- **2026-05-29** — fix merged (`6724d69`). Advisory GHSA-v9pm-47h4-jcq8 published; assigned CVE-2026-50538.

The 5-day window between discovery (May 24) and a merged public fix (May 29) represents an exceptionally fast and efficient patching cycle for an open-source project.

## Takeaways

- **In a client/server protocol, the server is an attack surface.** Every field the server controls is a potential input for you to treat as hostile.
- **Validate the size that drives the write, not the size that was declared.** Decompressors break this all the time.
- **Match the existing safe pattern.** The fix wasn't clever; the sibling decoders already did it right. The bug was one path that didn't.

*Reported by Bas Levering. Thanks to the LibVNC maintainers for a fast turnaround.*

## A note on the journey

The entire research process, from the initial static code analysis to the final patch, was heavily driven by leveraging Anthropic's Claude Opus 4.7 model. To my surprise, Claude Code can fully automate the process of finding and disclosing critical bugs in public infrastructure.

The hard part for the user driving the prompting is:

- **Bypassing hallucinations and intended-design false flags** — that's what the PoCs and Docker labs are good for.
- **Battling Anthropic's anti-malware safeguards** — if you are not verified in the customer verification program, it will often block you from writing PoC scripts.
- **Pointing it in the right direction** and giving it a framework to work with, so it filters out bad paths to take and rabbit holes to go down into.

My main objective is often to verify and determine the actual impact of the findings in the labs and code analysis before sending anything to developers, so they don't get overrun with pointless advisory spam.

I've been going crazy with this. So far I've audited ~100 different libraries and software packages, and my findings are slightly worrying and comforting at the same time: a bunch of software I actually use is well tested and locked down, but at the same time there seems to be a lot of footgun configurations, trust issues and meme bugs.

Thanks to everyone who made it this far into the article!
